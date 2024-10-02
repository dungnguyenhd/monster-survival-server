# Stage 1: Build
FROM node:20 AS build

WORKDIR /app
COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile
COPY . .

# Stage 2: Production
FROM node:20

WORKDIR /app
COPY --from=build /app /app
COPY --from=build /app/node_modules /app/node_modules

CMD ["yarn", "start"]
