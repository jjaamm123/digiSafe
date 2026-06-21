import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';
import scanRouter from './routes/scan.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Enable CORS for local development and chrome extension access
app.use(cors({
  origin: '*', // In production, restrict this to specific extension IDs: chrome-extension://<id>
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body parser middleware for JSON payloads
app.use(express.json());

// Root health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Register Scan Router
app.use('/api', scanRouter);

// Centralized error handling middleware
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
