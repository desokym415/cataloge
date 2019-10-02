#!/usr/bin/env python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from item_catalog_database import Category, Base, Item

#engine = create_engine('sqlite:///categorymenu.db')
engine = create_engine('postgresql://catalog:password@localhost/catalog')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

"1"
snowboarding = Category(cat_name="Snowboarding")
session.add(snowboarding)
session.commit()
"2"
soccer = Category(cat_name="Soccer")
session.add(soccer)
session.commit()
"3"
basketball = Category(cat_name="Basketball")
session.add(basketball)
session.commit()
"4"
baseball = Category(cat_name="Baseball")
session.add(baseball)
session.commit()
"5"
frisbee = Category(cat_name="Frisbee")
session.add(frisbee)
session.commit()
"6"
football = Category(cat_name="Football")
session.add(football)
session.commit()
"7"
skating = Category(cat_name="Skating")
session.add(skating)
session.commit()
"8"
hockey = Category(cat_name="Hockey")
session.add(hockey)
session.commit()
"9"
rock_climbing = Category(cat_name="Rock climbing")
session.add(rock_climbing)
session.commit()
"1"
snowboard = Item(
    item_name="snowboard", description="""Best for any terrain and
    conditions. All mountain snowboards
    perform anywhere on a mountain groomed runs,
    backcountry, even park and pipe. They may be directional
    (meaning they are intended to be ridden primarily in one direction) or
    twin (for riding switch, meaning either direction).
    Most boarders ride all mountain boards.
    Because of their versatility,
    all mountain boards are good for beginners who are
    still learning what terrain they like.""",
    category=snowboarding)
session.add(snowboard)
session.commit()

"2"
hockey_stick = Item(
    item_name="hockey stick", description="""a stick to kick the ball""",
    category=hockey)
session.add(hockey_stick)
session.commit()

print("added some categories and items")
