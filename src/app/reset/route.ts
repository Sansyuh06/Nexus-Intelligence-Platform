import { NextResponse } from 'next/server';

export async function POST() {
    return NextResponse.json({
        observation: "Environment successfully reset and ready for Next.js vulnerability scanning.",
        state: "READY",
        info: {}
    });
}
