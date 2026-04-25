import { NextResponse } from 'next/server';

async function proxyState() {
  try {
    const response = await fetch('http://localhost:8000/state');
    if (!response.ok) {
      return NextResponse.json({ error: 'FastAPI unavailable' }, { status: 502 });
    }
    const data = await response.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error('Error proxying /state to FastAPI:', error);
    return NextResponse.json({ error: 'FastAPI unavailable' }, { status: 502 });
  }
}

export async function GET() {
  return proxyState();
}

export async function POST() {
  return proxyState();
}