"""DynamoDB storage.

Table layout is one table per model, named `{prefix}{Model}s`, partitioned on
the model's id, with a `by_account` GSI on `account_id` so the common query
("everything for this account") is a query rather than a scan.

Two DynamoDB specifics this module handles rather than leaving to bite later:

  * DynamoDB has no float type. Every number must be a Decimal on the way in
    and back to float on the way out, or a `Float types are not supported`
    error appears the first time a saving lands on a non-integer.
  * DynamoDB rejects empty strings inside sets, and historically inside
    attributes. Empty strings are stored as nulls and restored as None, which
    pydantic then fills with the field default.

Audit records are written with a condition that the id does not already exist,
so an audit entry can never be silently overwritten.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any, Generic, TypeVar

from botocore.exceptions import ClientError

from ..config import Settings, get_settings
from ..models.domain import (
    Account,
    Action,
    AuditLog,
    Finding,
    Recommendation,
    Resource,
    Scan,
)
from .base import KEY_FIELDS

logger = logging.getLogger(__name__)

T = TypeVar("T")

ACCOUNT_INDEX = "by_account"


def _to_dynamo(value: Any) -> Any:
    """floats -> Decimal, recursively. DynamoDB has no float type."""
    if isinstance(value, float):
        # str() first: Decimal(0.1) carries binary float error into the store.
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: _to_dynamo(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_dynamo(v) for v in value]
    return value


def _from_dynamo(value: Any) -> Any:
    if isinstance(value, Decimal):
        as_int = int(value)
        return as_int if value == as_int else float(value)
    if isinstance(value, dict):
        return {k: _from_dynamo(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_from_dynamo(v) for v in value]
    return value


class DynamoRepository(Generic[T]):
    def __init__(self, model: type[T], settings: Settings | None = None) -> None:
        import boto3

        self._settings = settings or get_settings()
        self._model = model
        self._key = KEY_FIELDS[model.__name__]
        self.table_name = f"{self._settings.dynamodb_table_prefix}{model.__name__}s"

        kwargs: dict[str, Any] = {"region_name": self._settings.aws_region}
        if self._settings.dynamodb_endpoint_url:
            kwargs["endpoint_url"] = self._settings.dynamodb_endpoint_url
        self._table = boto3.resource("dynamodb", **kwargs).Table(self.table_name)

    # ------------------------------------------------------------------

    def get(self, key: str) -> T | None:
        try:
            response = self._table.get_item(Key={self._key: key})
        except ClientError as exc:
            logger.error("dynamodb get failed on %s: %s", self.table_name, exc)
            raise
        item = response.get("Item")
        return self._deserialize(item) if item else None

    def put(self, item: T) -> T:
        payload = _to_dynamo(item.model_dump(mode="json"))
        try:
            if self._model is AuditLog:
                # Audit entries are append-only. Refuse to overwrite one.
                self._table.put_item(
                    Item=payload,
                    ConditionExpression=f"attribute_not_exists({self._key})",
                )
            else:
                self._table.put_item(Item=payload)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                logger.warning(
                    "refused to overwrite existing audit record %s",
                    getattr(item, self._key),
                )
                return item
            logger.error("dynamodb put failed on %s: %s", self.table_name, exc)
            raise
        return item

    def list(self, account_id: str | None = None, limit: int = 1000) -> list[T]:
        items: list[dict] = []
        try:
            if account_id:
                kwargs = {
                    "IndexName": ACCOUNT_INDEX,
                    "KeyConditionExpression": "account_id = :a",
                    "ExpressionAttributeValues": {":a": account_id},
                    "Limit": limit,
                }
                while True:
                    response = self._table.query(**kwargs)
                    items.extend(response.get("Items", []))
                    token = response.get("LastEvaluatedKey")
                    if not token or len(items) >= limit:
                        break
                    kwargs["ExclusiveStartKey"] = token
            else:
                kwargs = {"Limit": limit}
                while True:
                    response = self._table.scan(**kwargs)
                    items.extend(response.get("Items", []))
                    token = response.get("LastEvaluatedKey")
                    if not token or len(items) >= limit:
                        break
                    kwargs["ExclusiveStartKey"] = token
        except ClientError as exc:
            logger.error("dynamodb list failed on %s: %s", self.table_name, exc)
            raise
        return [self._deserialize(i) for i in items[:limit]]

    def delete(self, key: str) -> bool:
        try:
            self._table.delete_item(
                Key={self._key: key}, ReturnValues="ALL_OLD"
            )
        except ClientError as exc:
            logger.error("dynamodb delete failed on %s: %s", self.table_name, exc)
            raise
        return True

    def _deserialize(self, item: dict) -> T:
        return self._model(**_from_dynamo(item))


class DynamoRepositories:
    def __init__(self, settings: Settings | None = None) -> None:
        settings = settings or get_settings()
        self.accounts = DynamoRepository(Account, settings)
        self.resources = DynamoRepository(Resource, settings)
        self.findings = DynamoRepository(Finding, settings)
        self.recommendations = DynamoRepository(Recommendation, settings)
        self.actions = DynamoRepository(Action, settings)
        self.audit = DynamoRepository(AuditLog, settings)
        self.scans = DynamoRepository(Scan, settings)


TABLE_MODELS = (Account, Resource, Finding, Recommendation, Action, AuditLog, Scan)


def table_definitions(prefix: str = "CloudWaste") -> list[dict]:
    """CreateTable inputs, used by the IaC and by local DynamoDB setup."""
    definitions = []
    for model in TABLE_MODELS:
        key = KEY_FIELDS[model.__name__]
        definition: dict[str, Any] = {
            "TableName": f"{prefix}{model.__name__}s",
            "KeySchema": [{"AttributeName": key, "KeyType": "HASH"}],
            "AttributeDefinitions": [{"AttributeName": key, "AttributeType": "S"}],
            "BillingMode": "PAY_PER_REQUEST",
        }
        if model is not Account:
            definition["AttributeDefinitions"].append(
                {"AttributeName": "account_id", "AttributeType": "S"}
            )
            definition["GlobalSecondaryIndexes"] = [
                {
                    "IndexName": ACCOUNT_INDEX,
                    "KeySchema": [{"AttributeName": "account_id", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ]
        definitions.append(definition)
    return definitions
