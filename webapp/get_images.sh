#!/bin/bash

mysql_container=$(docker ps | grep $(docker compose ps | grep mysql | cut -f 1 -d ' ') | cut -f 1 -d ' ')
docker exec -it $mysql_container mysql -u root -proot -D isuconp -e "SELECT id, mime from posts;" > _get_image.sh

# -e 's#\(\.[a-zA-z]*\)#\1 \&#g' -e 's#\n##g'
gsed -i'' -e '$d' -e '1,4d' -e 's#| *##g' -e 's# image/#\.#g' -e 's#jpeg#jpg#g' -e 's#^#http://localhost/image/#g' -e 's#^#curl -sO #g'  _get_image.sh
chmod +x _get_image.sh
mkdir -p public/image
cd public/image
../../_get_image.sh
rm -rf ../../_get_image.sh