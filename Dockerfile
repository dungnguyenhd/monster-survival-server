# Sử dụng Node.js phiên bản mới nhất
FROM node:20

# Thiết lập thư mục làm việc
WORKDIR /usr/src/app

# Sao chép tệp package.json và yarn.lock (nếu có)
COPY package.json yarn.lock ./

# Cài đặt dependencies
RUN yarn install

# Sao chép mã nguồn còn lại
COPY . .

# Biên dịch ứng dụng
RUN npm run build

# Expose cổng 8080
EXPOSE 8080

# Chạy ứng dụng
CMD ["node", "dist/main.js"]
