FROM node:latest
WORKDIR /usr/app
COPY ../idp.js .
# install dependencies
RUN npm install express
RUN npm install jsonwebtoken
RUN npm install shasum
EXPOSE 3000
ENTRYPOINT [ "node", "/usr/app/idp.js" ]
