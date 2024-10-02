# Stage 1: Build
FROM node:18-alpine AS build

WORKDIR /app
COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile
COPY . .

# Stage 2: Production
FROM node:18-alpine

WORKDIR /app
COPY --from=build /app /app
COPY --from=build /app/node_modules /app/node_modules

CMD ["yarn", "start"]
