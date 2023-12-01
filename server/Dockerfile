FROM node:18.14.2

WORKDIR /server

COPY ./package*.json ./
RUN npm install
COPY ./server.js ./

CMD ["npm", "run", "start"]