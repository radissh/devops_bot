#for database

FROM postgres:15.6

RUN apt-get update
RUN apt-get install gettext-base

COPY ./init.sql /docker-entrypoint-initdb.d/init.sql.raw
RUN mkdir -p /etc/postgresql/
RUN mkdir -p /oracle/pg_data/archive/
RUN chown postgres:postgres /oracle/pg_data/archive/

ENTRYPOINT [ "bash", "-c", "\
mkdir -p /var/log/postgresql/ \n\
chown postgres:postgres /var/log/postgresql/ \n\
envsubst < /docker-entrypoint-initdb.d/init.sql.raw > /docker-entrypoint-initdb.d/init.sql \n\
cat <<EOF > /etc/postgresql/postgresql.conf \n\
listen_addresses = '*' \n\
port = ${DB_PORT} \n\
log_destination = 'stderr' \n\
logging_collector = on \n\
log_directory = '/var/log/postgresql/' \n\
log_filename = 'postgresql.log' \n\
archive_mode = on \n\
archive_command = 'cp %p /oracle/pg_data/archive/%f' \n\
max_wal_senders = 10 \n\
wal_level = replica \n\
wal_log_hints = on \n\
log_replication_commands = on \n\
EOF\n\
cat <<EOF > /etc/postgresql/pg_hba.conf \n\
local all ${POSTGRES_USER} peer \n\
host all all 0.0.0.0/0 password \n\
host replication ${DB_REPL_USER} ${DB_REPL_HOST} trust \n\
EOF\n\
docker-entrypoint.sh $@"]

CMD ["postgres", "-c", "config_file=/etc/postgresql/postgresql.conf", "-c", "hba_file=/etc/postgresql/pg_hba.conf" ]
