// API Route pour l'authentification
import { NextResponse } from 'next/server';
import { executeQuery } from '@/lib/db';
import jwt from 'jsonwebtoken';

const JWT_SECRET = "mon_secret_jwt";

export async function POST(request: Request) {
  try {
    const credentials = await request.json();

    // Prevent malformed payloads by checking types explicitly
    if (
      typeof credentials?.username !== 'string' ||
      typeof credentials?.password !== 'string'
    ) {
      return NextResponse.json(
        { error: 'Requête invalide' },
        { status: 400 }
      );
    }

    const { username, password } = credentials;
    
    // Prevent SQL injection by using parameterized query
    const result = await executeQuery(
      'SELECT * FROM users WHERE username = $1 AND password = $2',
      [username, password]
    );

    if (result.rows.length > 0) {
      const user = result.rows[0];

      const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET);

      // Return token and user info (Password is deliberately excluded for security reasons)
      return NextResponse.json({
        token,
        user: {
          id: user.id,
          username: user.username
        }
      });
    } else {
      return NextResponse.json({ error: 'Identifiants incorrects' }, { status: 401 });
    }
  } catch (error) {
    console.error('Erreur lors de la connexion:', error);
    return NextResponse.json({ error: 'Erreur serveur' }, { status: 500 });
  }
}
