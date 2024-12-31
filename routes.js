// Assuming all routers are in separate files

// artistsRouter.js
import express from "express";
const artistsRouter = express.Router();
import db from './db.js'; // Import the database configuration

artistsRouter.get('/artists', async (req, res) => {
  try {
    const artists = await db.query('SELECT * FROM artists');
    res.render('artists', { title: 'Find Artists', artists: artists.rows });
  } catch (err) {
    console.error('Error fetching artists:', err);
    res.status(500).send('Error fetching artists');
  }
});

export { artistsRouter };

// eventsRouter.js
import express from "express";
const eventsRouter = express.Router();
import db from './db.js'; // Import the database configuration

eventsRouter.get('/events', async (req, res) => {
  try {
    const events = await db.query('SELECT * FROM events');
    // Assuming you want to display all events data:
    res.render('events', { title: 'Upcoming Events', events: events.rows });
  } catch (err) {
    console.error('Error fetching events:', err);
    res.status(500).send('Error fetching events');
  }
});

export { eventsRouter };

// bandsRouter.js (similar to artistsRouter.js)
import express from "express";
const bandsRouter = express.Router();
import db from './db.js'; // Import the database configuration

// ... (Rest of the bandsRouter code)

export default bandsRouter;

// connectionsRouter.js (Assuming it's in a separate file)
const express = require('express');
const connectionsRouter = express.Router();
const connectionsController = require('../controllers/connectionsController');

// Fetch all connections
connectionsRouter.get('/', connectionsController.getConnections);

// Search users by name
connectionsRouter.get('/search', connectionsController.searchUsersByName);

// Send a connection request
connectionsRouter.post('/send', connectionsController.sendConnectionRequest);

// Update connection status
connectionsRouter.post('/update', connectionsController.updateConnectionStatus);

module.exports = connectionsRouter;