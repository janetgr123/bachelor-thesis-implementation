# create docker container
docker compose -p $1 -f docker-compose.yml up -d

# wait for container to be running
sleep 10

# connect to psql
psql -U bt -h 127.0.0.1 -p 5432 -d bt

