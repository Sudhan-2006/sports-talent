import { app } from './server';

app.use('/uploads', static(join(__dirname, 'uploads')));
