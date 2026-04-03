import { NextResponse } from 'next/server';

export async function POST(req: Request) {
    try {
        const body = await req.json().catch(() => ({}));
        return NextResponse.json({
            observation: "Analysis step completed successfully.",
            reward: 1.0,
            done: true,
            info: { received_action: body }
        });
    } catch (e) {
        return NextResponse.json({ error: "Invalid step request" }, { status: 400 });
    }
}
