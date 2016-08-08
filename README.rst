========
Gotthard
========
Gotthard is a command line tool to simplify connecting to a PostgreSQL instance via a bastion_ host.
This tool is created in the context of zalando-stups_, however it could be used without it.

.. contents::
    :local:
    :depth: 2

Installation
============

.. code-block:: bash

  $ sudo pip3 install --upgrade gotthard

Configuration
=============
Gotthard does not have its own configuration. It uses the `piu configuration`_ file.

Usage
=====
Gotthard can provide help with the commands itself:

.. code-block:: bash

  $ gotthard --help

Gotthard can run in two basic modes: in the foreground and in the background.

When running in the background, gotthard establishes a tunnel and keeps the tunnel running in the background.

.. code-block:: bash

  $ gotthard shipping.logistics.db.example.com

When running in the foreground, the tunnel is established and the command you specify is executed.
Once your command finishes, the tunnel is closed. If you need to pass options to the command, you
will have to add the ``--`` to signify that the following options should not be interpreted by gotthard.

.. code-block:: bash

  $ gotthard shipping.logistics.db.example.com psql
  $ gotthard shipping.logistics.db.example.com -- psql -U myusername

Stups: Requesting access to odd
-------------------------------
When using even & odd, the command will only succeed if you have been granted access to the odd host you are
trying to connect to. You can request access manually, but you can also have gotthard take care of this. When
specifying a reason, gotthard will actually execute a ``piu request-access`` for you.

.. code-block:: bash

  $ gotthard shipping.logistics.db.example.com --reason="Investigating INCIDENT-123" psql

Connecting to a local Spilo
---------------------------
If you want to connect to a Spilo_ that is running in the same network as your odd-host, you can use
the name of the Spilo appliance to connect.
This does however require you to be logged in to your AWS account, as we need to query your account.

.. code-block:: bash

  $ gotthard shippinglogistics psql

How does it actually work
================
The way Gotthard works is by setting up an ssh tunnel to the bastion host.
It chooses the local port specified a free local port to tunnel the requests to remote side to port 5432.

When running in the background, it's task is done: It will report back the details of the tunnel.

When running in the foregroed, Gotthard will export the PostgreSQL related `Environment Variables`_ to the process
it needs to run. Most PostgreSQL client tools will use these environment variables to connect, most of your python or
perl scripts should adhere to these variables as well.

.. code-block:: bash

  $ gotthard shippinglogistics env | grep PG
  PGUSER=username
  PGHOST=localhost
  PGDATABASE=postgres
  PGPORT=52296
  PGSSLMODE=require

Examples
========

Export a database
-----------------

.. code-block:: bash

  $ gotthard shipping.logistics.db.example.com --reason="FEATURE-123" -- pg_dump -d fancydb -Fc -f fancydb.dump

Get the size of an RDS database
-------------------------------

.. code-block:: bash

  $ query="SELECT pg_database_size(CURRENT_CATALOG)"
  $ gotthard example.us-west-2.rds.amazonaws.com -- psql -U rds_admin -d featuredb -c "$query"

Duplicate a Spilo database to your machine
------------------------------------------
This actually requires you to have replication privileges.

.. code-block:: bash

  $ gotthard shippinglogistics -- pg_basebackup -D /postgres/mydata



.. _bastion: https://en.wikipedia.org/wiki/Bastion_host
.. _zalando-stups: https://github.com/zalando-stups
.. _piu configuration: http://stups.readthedocs.io/en/latest/components/piu.html#how-to-configure
.. _Spilo: https://github.com/zalando/spilo
.. _Environment variables: https://www.postgresql.org/docs/current/static/libpq-envars.html
