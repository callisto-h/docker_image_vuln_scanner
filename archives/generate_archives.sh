docker pull mongo:latest 
docker pull redis:latest
docker pull nginx:latest 
docker pull alpine:latest
docker pull centos/postgresql-10-centos7:latest

docker save mongo:latest > mongo.tar
docker save redis:latest > redis.tar
docker save nginx:latest > nginx.tar
docker save alpine:latest > alpine.tar
docker save centos/postgresql-10-centos7:latest > centos.tar

# don't run this in the vscode terminal, for some reason the `docker save` functionality
# would only work