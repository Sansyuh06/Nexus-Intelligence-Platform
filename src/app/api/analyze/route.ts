import { NextResponse } from 'next/server';
import { GoogleGenerativeAI } from '@google/generative-ai';

// Types
type AnalyzeRequest = {
  githubUrl: string;
};

type FileNode = {
  path: string;
  type: string;
  size?: number;
  url: string;
};

// Model fallback chain — if one model is rate-limited, try the next
const MODEL_CHAIN = ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-1.5-flash'];

async function callGeminiWithRetry(prompt: string, apiKey: string): Promise<string> {
  const genAI = new GoogleGenerativeAI(apiKey);

  for (const modelName of MODEL_CHAIN) {
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        console.log(`[Gemini] Trying ${modelName} (attempt ${attempt + 1})...`);
        const model = genAI.getGenerativeModel({ model: modelName });
        const aiResponse = await model.generateContent(prompt);
        const text = aiResponse.response.text();
        console.log(`[Gemini] Success with ${modelName}`);
        return text;
      } catch (err: any) {
        const is429 = err?.message?.includes('429') || err?.status === 429;
        if (is429 && attempt < 2) {
          const delay = Math.pow(2, attempt + 1) * 1000; // 2s, 4s
          console.warn(`[Gemini] 429 on ${modelName}, retrying in ${delay}ms...`);
          await new Promise(r => setTimeout(r, delay));
          continue;
        }
        if (is429) {
          console.warn(`[Gemini] ${modelName} exhausted, falling back...`);
          break; // try next model in chain
        }
        throw err; // non-429 error, bubble up
      }
    }
  }
  throw new Error('All Gemini models are rate-limited. Please wait a minute and try again.');
}

export async function POST(req: Request) {
  try {
    if (!process.env.GEMINI_API_KEY) {
      return NextResponse.json({ error: 'GEMINI_API_KEY server configuration is missing.' }, { status: 500 });
    }

    const body: AnalyzeRequest = await req.json();
    const { githubUrl } = body;

    if (!githubUrl || !githubUrl.includes('github.com')) {
      return NextResponse.json({ error: 'Please provide a valid GitHub repository URL.' }, { status: 400 });
    }

    // Extract owner and repo
    const urlParts = githubUrl.split('github.com/')[1].split('/');
    const owner = urlParts[0];
    const repo = urlParts[1]?.replace('.git', '');

    if (!owner || !repo) {
      return NextResponse.json({ error: 'Could not parse owner and repository from URL.' }, { status: 400 });
    }

    // 1. Fetch Repository Default Branch & Tree SHA
    console.log(`[API] Fetching repo info for ${owner}/${repo}...`);
    const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: process.env.GITHUB_TOKEN ? { Authorization: `token ${process.env.GITHUB_TOKEN}` } : {},
    });

    if (!repoRes.ok) {
      return NextResponse.json({ error: `GitHub API error: ${repoRes.statusText}. Repo might be private or invalid.` }, { status: repoRes.status });
    }

    const repoData = await repoRes.json();
    const defaultBranch = repoData.default_branch;

    // 2. Fetch Recursive Tree
    console.log(`[API] Fetching git tree recursively for branch ${defaultBranch}...`);
    const treeRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/${defaultBranch}?recursive=1`, {
      headers: process.env.GITHUB_TOKEN ? { Authorization: `token ${process.env.GITHUB_TOKEN}` } : {},
    });

    if (!treeRes.ok) {
      return NextResponse.json({ error: 'Failed to fetch repository tree structure.' }, { status: treeRes.status });
    }

    const treeData = await treeRes.json();
    
    // Filter for actionable source code files
    const validExtensions = ['.js', '.jsx', '.ts', '.tsx', '.py', '.go', '.java', '.php', '.rb', '.c', '.cpp', '.cs'];
    const maxFiles = 30;
    
    let sourceFiles: FileNode[] = treeData.tree
      .filter((file: FileNode) => file.type === 'blob')
      .filter((file: FileNode) => validExtensions.some(ext => file.path.endsWith(ext)))
      .filter((file: FileNode) => !file.path.includes('node_modules') && !file.path.includes('vendor') && !file.path.includes('dist'));

    sourceFiles = sourceFiles.slice(0, maxFiles);

    if (sourceFiles.length === 0) {
      return NextResponse.json({ error: 'No supported source code files found to analyze in this repository.' }, { status: 404 });
    }

    // 3. Download Source Code Contents in Parallel
    console.log(`[API] Downloading ${sourceFiles.length} source code files...`);
    const fileContents: { path: string; content: string }[] = [];
    
    for (let i = 0; i < sourceFiles.length; i += 5) {
        const batch = sourceFiles.slice(i, i + 5);
        const fetches = batch.map(async (f) => {
            const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${defaultBranch}/${f.path}`;
            const res = await fetch(rawUrl);
            if (res.ok) {
                const text = await res.text();
                return { path: f.path, content: text };
            }
            return null;
        });
        
        const results = await Promise.all(fetches);
        for (const res of results) {
            if (res) fileContents.push(res);
        }
    }

    // 4. Construct Prompt
    console.log(`[API] Assembling code context for Gemini Analysis...`);
    let codeContext = fileContents.map(f => `--- FILE: ${f.path} ---\n${f.content}\n`).join('\n');
    
    if (codeContext.length > 500000) {
        codeContext = codeContext.substring(0, 500000) + "\n...[TRUNCATED DUE TO SIZE]...";
    }

    const prompt = `You are a Senior Security Auditor and SAST Tool. 
Analyze the following source code repository contents.
Identify ANY severe vulnerabilities, bugs, hardcoded secrets, injection vectors, or logical flaws.

Return a JSON array of perfectly formatted vulnerability objects matching this exact Typescript interface:
\`\`\`typescript
interface Vulnerability {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  title: string;
  description: string;
  file: string;      // The path of the file where it was found
  lineSnippet: string; // The specific vulnerable lines of code (max 5 lines)
  suggestion: string; // How to fix it
}
\`\`\`

If no vulnerabilities are found, return an empty array [].
Do NOT wrap the response in markdown \`\`\`json. Return RAW JSON only.

REPOSITORY CODE:
${codeContext}
`;

    // 5. Fire Request to Gemini with retry + fallback
    console.log(`[API] Analyzing with Gemini (retry-enabled)...`);
    let responseText = await callGeminiWithRetry(prompt, process.env.GEMINI_API_KEY);
    
    // Strip markdown fences if Gemini added them despite prompt
    responseText = responseText.replace(/^```(json)?/, '').replace(/```$/, '').trim();

    try {
      const parsedResults = JSON.parse(responseText);
      return NextResponse.json({
          repository: `${owner}/${repo}`,
          filesScanned: fileContents.length,
          vulnerabilities: parsedResults
      });
    } catch (parseError) {
      console.error("Failed to parse Gemini output", responseText);
      return NextResponse.json({ error: 'AI analysis returned invalid format.', raw_output: responseText }, { status: 502 });
    }

  } catch (error: any) {
    console.error("[API] Fatal Analyze Error:", error);
    return NextResponse.json({ error: error.message || 'Internal Server Error' }, { status: 500 });
  }
}


