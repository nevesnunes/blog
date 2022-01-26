---
layout: post
title: Database Tunneling
date: 2019-06-14 00:00:00 +0100
tags: 
    - networking
    - relays
---

In order to run a database client locally, a SSH tunnel was made to a remote host. However, the connection from localhost to the database service was refused, while hosts on the same remote subnet were able to connect.

## Analysis

The tunnel was started from `local_client`, connecting to the SSH server at `remote_entrypoint`, and forwarding traffic to the database host `remote_database` (with IP `10.55.55.5`):

```sh
ssh foo@remote_entrypoint -L 1521:10.55.55.5:1521 -N -vvv
```

We can ping `remote_database` from `local_client`, and we know port `1521` was open by the Oracle SQL database server, by connecting with [`jdbc-tester`](https://github.com/aimtiaz11/oracle-jdbc-tester) from `remote_entrypoint`:

```sh
java -jar jdbc-tester-1.0.jar foo_user foo_pass 'jdbc:oracle:thin:@10.55.55.5:1521/FOO_SERVICE'
```

But the same test failed from `local_client`:

```sh
java -jar jdbc-tester-1.0.jar foo_user foo_pass 'jdbc:oracle:thin:@127.0.0.1:1521/FOO_SERVICE'
```

The service name also seemed to be recognized. Another way to test it would be with a TNS entry. To resolve `FOO_SERVICE` in localhost, we change the host referenced in `tnsnames.ora`:

```ora
FOO_LOCAL =
 (DESCRIPTION =
   (ADDRESS_LIST =
     (ADDRESS = (PROTOCOL = TCP)(HOST = localhost)(PORT = 1521))
   )
 (CONNECT_DATA =
   (SERVICE_NAME = FOO_SERVICE)
 )
)
```

Then we check if the database listener is available with [`McTnsping`](http://www.orafaq.com/wiki/tnsping) (error `0` is returned, which encodes success):

```sh
./McTnsping.exe -dir tnsnames/ -t FOO_LOCAL
```

Database clients were also complaining about network issues:

DBeaver:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/img/dbeaver.png" alt="DBeaver error"/>
</div>

SQLcl:
```sh
./sql.exe 'foo_user/foo_pass@jdbc:oracle:thin:@//localhost:1521/FOO_SERVICE'

# SQLcl: Release 19.1 Production on Fri Jun 14 17:17:51 2019
# 
# Copyright (c) 1982, 2019, Oracle.  All rights reserved.
# 
#   USER          = foo_user
#   URL           = jdbc:oracle:thin:@//localhost:1521/FOO_SERVICE
#   Error Message = IO Error: The Network Adapter could not establish the connection
# Username? (RETRYING) ('foo_user/*********@jdbc:oracle:thin:@//localhost:1521/FOO_SERVICE'?)
```

SQL*Plus:
```sh
./sqlplus.exe 'foo_user/foo_pass@(DESCRIPTION = (ADDRESS_LIST = (ADDRESS = (PROTOCOL = TCP)(HOST = localhost)(PORT = 1521))) (CONNECT_DATA = (SERVICE_NAME = FOO_SERVICE)))'

# SQL*Plus: Release 19.0.0.0.0 - Production on Fri Jun 14 17:19:12 2019
# Version 19.3.0.0.0
# 
# Copyright (c) 1982, 2019, Oracle.  All rights reserved.
# 
# ERROR:
# ORA-12170: TNS:Connect timeout occurred
# 
# 
# Enter user-name:
# ERROR:
# ORA-12560: TNS:protocol adapter error
# 
# 
# Enter user-name:
# ERROR:
# ORA-12560: TNS:protocol adapter error
# 
# 
# SP2-0157: unable to CONNECT to ORACLE after 3 attempts, exiting SQL*Plus
```

## Show me the bytes

The actual network traffic should allow us to see what was different between connections from `local_client` and `remote_entrypoint`.

Unfortunately, user `foo` at `remote_entrypoint` wasn't an admin, so running `tcpdump` was out.

An alternative would be to forward TCP traffic from `remote_entrypoint:1521` to `remote_database:1521`, and have `local_client` connect to the former. This way, we could run an unprivileged application that dumps its forwarded traffic.

One way to accomplish that would be with 2 instances of `netcat` and a FIFO pipe (optionally storing the processed input and output in files):

```sh
mknod backpipe p && ( \
    trap 'rm -f backpipe' EXIT INT QUIT TERM && \
    nc -kl 127.0.0.1 1521 < backpipe | \
    tee -a 'in.txt' | \
    nc 10.55.55.5 1521 | \
    tee -a 'out.txt' > backpipe \
)
```

However I decided to use `socat` for this, as I preferred the formatted dumps it makes. After [statically compiling it](https://github.com/andrew-d/static-binaries/tree/master/socat/) and moving it to `remote_entrypoint`:

```sh
./socat -v -x -d -d TCP4-LISTEN:1521,reuseaddr,fork TCP4:10.55.55.5:1521
```

Then on `local_client`:

```sh
ssh foo@remote_entrypoint -L 1521:127.0.0.1:1521 -N -vvv
```

Now we get the luxury of having error codes:

```sh
java -jar jdbc-tester-1.0.jar foo_user foo_pass 'jdbc:oracle:thin:@127.0.0.1:1521/FOO_SERVICE'

# > 2019/06/14 15:38:28.930225  length=282 from=0 to=281
# .........6.,\fA ...O........:..............................(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521))(CONNECT_DATA=(CID=(PROGRAM=JDBC Thin Client)(HOST=__jdbc__)(USER=foo))(SERVICE_NAME=FOO_SERVICE)(CID=(PROGRAM=JDBC Thin Client)(HOST=__jdbc__)(USER=foo))))
# < 2019/06/14 15:38:28.940604  length=103 from=0 to=102
# .g......"..[(DESCRIPTION=(TMP=)(VSNNUM=301989888)(ERR=12516)(ERROR_STACK=(ERROR=(CODE=12516)(EMFI=4))))
```

But let's look at the actual response of the database server:

```sh
./sql.exe 'foo_user/foo_pass@jdbc:oracle:thin:@127.0.0.1:1521/FOO_SERVICE'

# > 2019/06/14 15:39:57.860357  length=230 from=0 to=229
# .........=.,\fA ...O........F................................ .. ......(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521))(CONNECT_DATA=(CID=(PROGRAM=SQLcl)(HOST=__jdbc__)(USER=local_foo))(SERVICE_NAME=FOO_SERVICE)))
# < 2019/06/14 15:39:57.861883  length=276 from=0 to=275
# .
# .........
# .......@(ADDRESS=(PROTOCOL=TCP)(HOST=10.55.55.2)(PORT=1521)).(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521))(CONNECT_DATA=(CID=(PROGRAM=SQLcl)(HOST=__jdbc__)(USER=local_foo))(SERVICE_NAME=FOO_SERVICE)(SERVER=dedicated)(INSTANCE_NAME=FOO_SERVICE2)))
```

```sh
./sqlplus.exe 'foo_user/foo_pass@(DESCRIPTION = (ADDRESS_LIST = (ADDRESS = (PROTOCOL = TCP)(HOST = localhost)(PORT = 1521))) (CONNECT_DATA = (SERVICE_NAME = FOO_SERVICE)))'

# > 2019/06/14 15:42:25.934838  length=323 from=0 to=322
# .J.......>.,\fA ............J....AA.......................... .. ....................(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521)(HOSTNAME=localhost))(CONNECT_DATA=(SERVICE_NAME=FOO_SERVICE)(CID=(PROGRAM=C:\\Users\\local_foo\\Downloads\\instantclient_19_3\\sqlplus.exe)(HOST=local_client)(USER=local_foo))))
# < 2019/06/14 15:42:25.936677  length=10 from=0 to=9
# .
# .
# .....O
# < 2019/06/14 15:42:25.936831  length=345 from=10 to=354
# .Y.
# .....@(ADDRESS=(PROTOCOL=TCP)(HOST=10.55.55.2)(PORT=1521)).(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521)(HOSTNAME=localhost))(CONNECT_DATA=(SERVICE_NAME=FOO_SERVICE)(CID=(PROGRAM=C:\\Users\\local_foo\\Downloads\\instantclient_19_3\\sqlplus.exe)(HOST=local_client)(USER=local_foo))(SERVER=dedicated)(INSTANCE_NAME=FOO_SERVICE2)))
```

The response comes from another IP: `10.55.55.2`! Oracle SQL can be configured to run [multiple instances for the same database](https://docs.oracle.com/cd/E11882_01/server.112/e40540/startup.htm#CNCPT89033). Our request from `local_client` was passing through without issues, but we only had a SSH tunnel for `10.55.55.5`. It turns out that we can just connect to the instance directly and have our clients working from `local_client`:

```sh
ssh foo@remote_entrypoint -L 1521:10.55.55.2:1521 -N -vvv
```

# Further work

A simple improvement for database clients: when a network connection fails, dump the remote hostname or IP of that connection attempt! Omitting this information misleads the user into assuming the database is self-contained on a single host.
