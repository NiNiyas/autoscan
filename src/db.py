import logging
import os
from datetime import datetime, timedelta

import config
from peewee import (
    Model,
    SqliteDatabase,
    CharField,
    IntegerField,
    DateTimeField,
    AutoField,
)

logger = logging.getLogger("DB")

# Config
conf = config.Config()

db_path = conf.settings["queuefile"]
database = SqliteDatabase(db_path)


class BaseQueueModel(Model):
    class Meta:
        database = database


class QueueItemModel(BaseQueueModel):
    scan_path = CharField(max_length=256, unique=True, null=False)
    scan_for = CharField(max_length=64, null=False)
    scan_section = IntegerField(null=False)
    scan_type = CharField(max_length=64, null=False)


class ScanHistoryModel(BaseQueueModel):
    id = AutoField()
    scan_path = CharField(max_length=512, null=False)
    scan_for = CharField(max_length=64, null=False)
    scan_type = CharField(max_length=64, null=False)
    scan_section = IntegerField(null=False)
    status = CharField(max_length=32, null=False)
    started_at = DateTimeField(null=True)
    completed_at = DateTimeField(null=True)
    error_message = CharField(max_length=512, null=True)
    platform = CharField(max_length=32, null=True)


def create_database(db, db_path):
    if not os.path.exists(db_path):
        db.create_tables([QueueItemModel, ScanHistoryModel])
        logger.info("Created Autoscan database tables.")


def connect(db):
    return db.connect() if db.is_closed() else False


def init(db, db_path):
    if not os.path.exists(db_path):
        create_database(db, db_path)
    connect(db)
    db.create_tables([ScanHistoryModel], safe=True)
    try:
        columns = [c.name for c in db.get_columns("scanhistorymodel")]
        if "platform" not in columns:
            logger.info("Migrating database: Adding platform column to scanhistorymodel")
            db.execute_sql("ALTER TABLE scanhistorymodel ADD COLUMN platform VARCHAR(32)")
    except Exception as e:
        logger.error(f"Database migration failed: {e}")


def get_next_item():
    item = None
    try:
        item = QueueItemModel.get()
    except Exception:
        # logger.exception("Exception getting first item to scan: ")
        pass
    return item


def exists_file_root_path(file_path):
    items = get_all_items()
    if "." in file_path:
        dir_path = os.path.dirname(file_path)
    else:
        dir_path = file_path

    for item in items:
        if dir_path.lower() in item["scan_path"].lower():
            return True, item["scan_path"]
    return False, None


def get_all_items():
    items = []
    try:
        for item in QueueItemModel.select():
            items.append(
                {
                    "scan_path": item.scan_path,
                    "scan_for": item.scan_for,
                    "scan_type": item.scan_type,
                    "scan_section": item.scan_section,
                }
            )
    except Exception:
        logger.exception("Exception getting all items from Autoscan database: ")
        return None
    return items


def get_queue_count():
    count = 0
    try:
        count = QueueItemModel.select().count()
    except Exception:
        logger.exception(
            "Exception getting queued item count from Autoscan database: "
        )
    return count


def remove_item(scan_path):
    try:
        return (
            (QueueItemModel.delete())
            .where(QueueItemModel.scan_path == scan_path)
            .execute()
        )
    except Exception:
        logger.exception(
            f"Exception deleting {scan_path} from Autoscan database: "
        )
        return False


def add_item(scan_path, scan_for, scan_section, scan_type):
    item = None
    try:
        return QueueItemModel.create(
            scan_path=scan_path,
            scan_for=scan_for,
            scan_section=scan_section,
            scan_type=scan_type,
        )
    except AttributeError as ex:
        return item
    except Exception:
        pass
        # logger.exception(f"Exception adding {scan_path} to database: ")
    return item


def queued_count():
    try:
        return QueueItemModel.select().count()
    except Exception:
        logger.exception("Exception retrieving queued count: ")
    return 0


def add_history_item(
    scan_path,
    scan_for,
    scan_type,
    scan_section,
    status,
    started_at=None,
    completed_at=None,
    error_message=None,
    platform=None,
):
    try:
        return ScanHistoryModel.create(
            scan_path=scan_path,
            scan_for=scan_for,
            scan_type=scan_type,
            scan_section=scan_section,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            error_message=error_message,
            platform=platform,
        )
    except Exception:
        logger.exception(f"Exception adding {scan_path} to scan history: ")
    return None


def get_history_items(page=1, limit=20, scan_for=None, status=None):
    items = []
    try:
        query = ScanHistoryModel.select().order_by(ScanHistoryModel.id.desc())

        if scan_for:
            query = query.where(ScanHistoryModel.scan_for == scan_for)
        if status:
            query = query.where(ScanHistoryModel.status == status)

        offset = (page - 1) * limit
        query = query.offset(offset).limit(limit)

        for item in query:
            items.append(
                {
                    "id": item.id,
                    "scan_path": item.scan_path,
                    "scan_for": item.scan_for,
                    "scan_type": item.scan_type,
                    "scan_section": item.scan_section,
                    "status": item.status,
                    "started_at": item.started_at.isoformat()
                    if item.started_at
                    else None,
                    "completed_at": item.completed_at.isoformat()
                    if item.completed_at
                    else None,
                    "error_message": item.error_message,
                    "platform": item.platform,
                }
            )
    except Exception:
        logger.exception("Exception getting scan history items: ")
    return items


def get_history_item_by_id(item_id):
    try:
        item = ScanHistoryModel.get_or_none(ScanHistoryModel.id == item_id)
        if item:
            return {
                "id": item.id,
                "scan_path": item.scan_path,
                "scan_for": item.scan_for,
                "scan_type": item.scan_type,
                "scan_section": item.scan_section,
                "status": item.status,
                "started_at": item.started_at,
                "completed_at": item.completed_at,
                "error_message": item.error_message,
                "platform": item.platform,
            }
    except Exception:
        logger.exception(f"Exception getting history item {item_id}: ")
    return None


def get_history_count(scan_for=None, status=None):
    try:
        query = ScanHistoryModel.select()

        if scan_for:
            query = query.where(ScanHistoryModel.scan_for == scan_for)
        if status:
            query = query.where(ScanHistoryModel.status == status)

        return query.count()
    except Exception:
        logger.exception("Exception getting scan history count: ")
    return 0


def clear_history():
    try:
        deleted = ScanHistoryModel.delete().execute()
        logger.info(f"Cleared {deleted} item(s) from scan history.")
        return deleted
    except Exception:
        logger.exception("Exception clearing scan history: ")
    return 0

# Init
init(database, db_path)
