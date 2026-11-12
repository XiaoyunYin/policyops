"""0012 -> 0013 preserves old data and refuses to forget checkpoint/replay intent."""

import pytest

from policyops.persistence.importer import import_synthetic_world
from policyops.persistence.migrate import DataLossRefused, head
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops_testing.app_database import NewDatabase
from policyops_testing.checkpoint_cases import claimed


pytestmark = pytest.mark.postgres


def test_0013_preserves_populated_0012_and_empty_downgrade_reupgrade(new_app_database: NewDatabase) -> None:
    db = new_app_database("t21_upgrade", revision="0012")
    import_synthetic_world(auth=db.engine(AUTH_RUNTIME), app=db.engine(APP_RUNTIME))
    with db.superuser() as conn:
        proposals = conn.execute("SELECT id, body::text, status FROM app.action_proposals ORDER BY id").fetchall()
        messages = conn.execute("SELECT id, text_sha256 FROM app.case_messages ORDER BY id").fetchall()
    db.upgrade("0013")
    with db.superuser() as conn:
        assert conn.execute("SELECT id, body::text, status FROM app.action_proposals "
                            "ORDER BY id").fetchall() == proposals
        assert conn.execute("SELECT id, text_sha256 FROM app.case_messages ORDER BY id").fetchall() == messages
        assert conn.execute("SELECT DISTINCT creation_step, creation_request_sha256 "
                            "FROM app.action_proposals").fetchall() == [(None, None)]
    db.downgrade("0012")  # legacy proposals do not prevent removal of the unused addition
    assert db.current() == "0012"
    db.upgrade("0013")
    assert db.current() == "0013"
    with db.superuser() as conn:
        assert conn.execute("SELECT id, body::text, status FROM app.action_proposals "
                            "ORDER BY id").fetchall() == proposals


@pytest.mark.parametrize("allow_data_loss", [False, True])
def test_downgrade_refuses_nonempty_checkpoint_tables(new_app_database: NewDatabase, allow_data_loss: bool) -> None:
    from tests.integration.test_checkpoints import seed

    db = new_app_database("t21_nonempty")
    owner = claimed(db)
    seed(owner)
    with pytest.raises(DataLossRefused, match="checkpoints"):
        db.downgrade("0012", allow_data_loss=allow_data_loss)
    assert db.current() == "0013"
    with db.superuser() as conn:
        assert conn.execute("SELECT count(*) FROM checkpoints.writes").fetchone() == (1,)
    db.upgrade()  # transaction_per_migration already removed empty 0014 before the refusal
    assert db.current() == head()


def test_proposal_replay_intent_alone_prevents_downgrade(new_app_database: NewDatabase) -> None:
    db = new_app_database("t21_replay_downgrade", revision="0012")
    import_synthetic_world(auth=db.engine(AUTH_RUNTIME), app=db.engine(APP_RUNTIME))
    db.upgrade("0013")
    with db.superuser() as conn:
        # The pre-existing all-fields-except-status guard must protect the NEW columns, even for the owner.
        with pytest.raises(Exception, match="immutable"):
            conn.execute("UPDATE app.action_proposals SET creation_step = 1, creation_request_sha256 = %s",
                         ("a" * 64,))
        # Fault injection only: simulate an otherwise valid creation binding without any checkpoints.
        conn.execute("ALTER TABLE app.action_proposals DISABLE TRIGGER action_proposals_guard")
        conn.execute("UPDATE app.action_proposals SET creation_step = 1, creation_request_sha256 = %s",
                     ("a" * 64,))
        conn.execute("ALTER TABLE app.action_proposals ENABLE TRIGGER action_proposals_guard")
    for allow in (False, True):
        with pytest.raises(DataLossRefused, match="replay intent"):
            db.downgrade("0012", allow_data_loss=allow)
        assert db.current() == "0013"
