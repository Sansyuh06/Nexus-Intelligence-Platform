import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  try {
    let body = {};
    const text = await request.text();
    if (text) {
      body = JSON.parse(text);
    }
    const response = await fetch('http://localhost:8000/reset', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error('Error proxying to FastAPI:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}