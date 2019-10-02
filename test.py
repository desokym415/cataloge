#!/usr/bin/env python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from item_catalog_database import Category, Base, Item, User
 
#engine = create_engine('sqlite:///categorymenu.db')
engine = create_engine('postgresql://catalog:password@localhost/catalog')

Base.metadata.bind = engine
 
DBSession = sessionmaker(bind=engine)
session = DBSession()

categories = session.query(Category).all()
for cat in categories:
    print cat.cat_name
    print cat.id
    print cat.user_id

items = session.query(Item).all()
for itemaia in items:
    print itemaia.item_name
    print itemaia.id
    print itemaia.user_id

users = session.query(User).all()
for anyuser in users:
    print anyuser.email
    print anyuser.id
    print anyuser.name