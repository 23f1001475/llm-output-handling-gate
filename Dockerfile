FROM node:24-slim
WORKDIR /app
COPY . /app
EXPOSE 8080
CMD ["node", "server.js"]
