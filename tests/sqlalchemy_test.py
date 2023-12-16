"""
Testing integration with sqlalchemy
"""
import sqlalchemy.engine
from sqlalchemy.orm import Session
from sqlalchemy import select
from sqlalchemy_schema import User, Address
from fixtures import sqlalchemy_engine


def test_alchemy(sqlalchemy_engine: sqlalchemy.engine.Engine):
    with Session(sqlalchemy_engine) as session:
        spongebob = User(
            name="spongebob",
            fullname="Spongebob Squarepants",
            addresses=[Address(email_address="spongebob@sqlalchemy.org")],
        )
        sandy = User(
            name="sandy",
            fullname="Sandy Cheeks",
            addresses=[
                Address(email_address="sandy@sqlalchemy.org"),
                Address(email_address="sandy@squirrelpower.org"),
            ],
        )
        patrick = User(name="patrick", fullname="Patrick Star")
        session.add_all([spongebob, sandy, patrick])

        # Test select
        stmt = select(User).where(User.name.in_(["spongebob", "sandy"]))
        users = session.scalars(stmt)
        assert [spongebob, sandy] == list(users)
