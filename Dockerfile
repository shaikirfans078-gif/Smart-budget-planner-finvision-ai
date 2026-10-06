FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY backend/package*.json ./backend/
RUN cd backend && npm install --omit=dev && npm cache clean --force
COPY frontend ./frontend
COPY backend ./backend
RUN mkdir -p /app/backend/data && chown -R node:node /app/backend/data
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "backend/server.js"]
