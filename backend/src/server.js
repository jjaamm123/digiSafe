import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';
import scanRouter from './routes/scan.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors({
  origin: '*', 
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 204, // Chrome MV3 pre-flight expects 204
}));


app.options('*', cors());

app.use(express.json());

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.use('/api', scanRouter);

app.use((err, req, res, next) => {
  console.error('Error encountered:', err.stack || err);
  res.status(500).json({
    success: false,
    error: 'Internal Server Error',
    message: err.message || 'An unexpected error occurred'
  });
});

app.listen(PORT, () => {
  console.log(`==================================================`);
  console.log(`  Digital Safety Backend listening on port ${PORT}`);
  console.log(`  Health Check: http://localhost:${PORT}/health`);
  console.log(`  Scan Endpoint: http://localhost:${PORT}/api/scan`);
  console.log(`==================================================`);
});
