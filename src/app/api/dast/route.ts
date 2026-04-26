import { NextResponse } from 'next/server';

// Types
type DastRequest = {
  targetUrl: string;
};

export async function POST(req: Request) {
  try {
    const body: DastRequest = await req.json();
    const { targetUrl } = body;

    if (!targetUrl || (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://'))) {
      return NextResponse.json({ error: 'Please provide a valid URL starting with http:// or https://' }, { status: 400 });
    }

    console.log(`[DAST] Dynamic scan requested for ${targetUrl}`);

    // The DAST scanner relies on a Python tool that is not deployed in this
    // environment.  Return a clear message rather than crashing.
    return NextResponse.json(
      {
        error:
          'Dynamic scanning (DAST) is not available in this deployment. ' +
          'Use the Code Audit (SAST) tab to analyze GitHub repositories instead.',
      },
      { status: 501 },
    );
  } catch (error: any) {
    console.error("[DAST] Fatal Error:", error);
    return NextResponse.json({ error: error.message || 'Internal Server Error' }, { status: 500 });
  }
}
