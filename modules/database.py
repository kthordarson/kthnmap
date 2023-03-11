import os
import re
from inspect import isclass
from dataclasses import dataclass, fields, field, is_dataclass
from sqlalchemy import create_engine, MetaData, Column, Integer, update, text
from sqlalchemy.exc import (ArgumentError, CompileError, DataError, IntegrityError, OperationalError, ProgrammingError)
from sqlalchemy import create_engine, MetaData, Column, Integer, String, DateTime, Date, Boolean, ForeignKey
from sqlalchemy import Engine
from sqlalchemy.orm import (DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session)

import sqlalchemy
from loguru import logger
import datetime

def get_engine(dbtype: str) -> Engine:
	dbuser = os.getenv('nmapdbuser')
	dbpass = os.getenv('nmapdbpass')
	dbhost = os.getenv('nmapdbhost')
	dbname = os.getenv('nmapdbname')
	if dbtype == 'mysql':
		if not dbuser or not dbpass or not dbhost or not dbname:
			raise AttributeError(f'[db] missing db env variables')
		dburl = f"mysql+pymysql://{dbuser}:{dbpass}@{dbhost}/{dbname}?charset=utf8mb4"
		return create_engine(dburl)
	# return create_engine(dburl, pool_size=200, max_overflow=0)
	elif dbtype == 'postgresql':
		if not dbuser or not dbpass or not dbhost or not dbname:
			raise AttributeError(f'[db] missing db env variables')
		dburl = f"postgresql://{dbuser}:{dbpass}@{dbhost}/{dbname}"
		return create_engine(dburl)
	elif dbtype == 'sqlite':
		return create_engine('sqlite:///localscan.db', echo=False, connect_args={'check_same_thread': False})
	else:
		raise TypeError(f'[db] unknown dbtype {dbtype} ')

def drop_tables(engine):
	pass

def create_tables(session):
	pass


