FROM node:24-slim
WORKDIR /app
COPY . /app
EXPOSE 7860
CMD ["node", "server.js"]
