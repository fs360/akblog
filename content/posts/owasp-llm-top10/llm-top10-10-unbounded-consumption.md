---
title: "LLM Top 10 — #10: Unbounded Consumption"
date: 2026-04-12
draft: true
tags: [ai, llm-security, owasp]
series: ["OWASP LLM Top 10"]
weight: 10
---

# LLM Top 10 — #10: Unbounded Consumption

**When Your AI Eats Your Budget (and Your Infrastructure)**

---

## What It Is

Unbounded Consumption refers to attacks and failures that cause an LLM application to consume excessive resources — compute, memory, API calls, tokens, or money — in ways that degrade service, inflate costs, or deny availability. This is the LLM-specific evolution of Denial of Service (DoS), but with unique characteristics:

- **Financial DoS** — Attacks that don't crash your system but drain your budget through legitimate-looking API calls
- **Resource exhaustion** — Prompts designed to maximize token consumption, context window usage, or compute time
- **Recursive/infinite loops** — Agent architectures that get trapped in unbounded tool-call loops
- **Model extraction** — Systematic querying to reconstruct model capabilities or fine-tuning data
- **API abuse** — Exploiting LLM endpoints for purposes beyond their intended use (free compute, content generation, etc.)

## Why It Matters

LLM infrastructure has a fundamentally different cost model than traditional applications:

**Traditional web application:**
```
Request cost: ~$0.000001 (CPU microseconds + bandwidth)
1 million requests: ~$1
Budget risk: Low — even heavy abuse is affordable
```

**LLM application:**
```
Request cost: $0.01 - $1.00+ (depending on model, tokens, tools)
1 million requests: $10,000 - $1,000,000
Budget risk: EXTREME — abuse can bankrupt a startup overnight
```

A single API call to a large model with a full context window can cost more than serving an entire web application for a day. This inverts the economics of DoS: the attacker's cost is negligible (sending a request), while the defender's cost is significant (processing it with an LLM).

### Threat Scenarios

**Financial DoS:**
An attacker scripts requests to your AI chatbot, each with the maximum input length, requesting the maximum output length. At $0.15 per request, 100 requests per second burns $15/second — $54,000 per hour. Your API bill for the weekend: $2.6 million.

**Agent Loop:**
An AI agent is asked to "analyze all files in the repository." It calls the file-read tool, processes each file, decides it needs more context, reads related files, processes those, finds more references, reads those... The agent makes 50,000 tool calls before someone notices, consuming $3,000 in API costs and 8 hours of compute time.

**Wallet Exhaustion for Startups:**
A competitor discovers your AI-powered product offers generous free-tier access. They script automated queries to exhaust your LLM API budget, effectively shutting down your product by making it unaffordable to operate.

## How It Works

### Financial Denial of Service (Financial DoS)

The most straightforward attack. Exploit the cost asymmetry between sending and processing LLM requests:

```python
# Attacker script — costs the attacker nothing
import asyncio
import aiohttp

async def financial_dos(target_url, num_requests=10000):
    # Craft maximum-cost prompts
    expensive_prompt = "A" * 100000  # Fill context window
    expensive_prompt += "\n\nAnalyze every word above in detail. " \
                       "For each word, provide etymology, usage examples, " \
                       "synonyms, antonyms, and cultural context."
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        for _ in range(num_requests):
            tasks.append(session.post(target_url, json={
                "message": expensive_prompt,
                "max_tokens": 4096  # Request maximum output
            }))
        await asyncio.gather(*tasks)

# Cost to attacker: ~$0 (bandwidth only)
# Cost to defender: potentially thousands of dollars
```

### Prompt-Based Resource Exhaustion

Crafting prompts that maximize computational cost:

**1. Maximum Token Generation:**
```
Write a 10,000-word essay on the history of every country in the world. 
Include specific dates, names, and events. Be as detailed as possible.
```

**2. Reasoning-Intensive Prompts:**
```
Solve the following: Find all prime numbers between 1 and 1,000,000. 
For each prime, determine if it's also a twin prime, a Sophie Germain 
prime, and a Mersenne prime. Show your work for each.
```

**3. Context Window Stuffing:**
```
[100KB of text]
Now summarize the above text, then translate your summary into every 
language you know, then back-translate each into English.
```

### Agent Recursion and Tool-Call Loops

Autonomous agents can enter infinite or near-infinite loops:

```python
# Agent architecture vulnerable to unbounded recursion
async def agent_loop(task: str):
    while not is_complete(task):
        # Plan next action
        action = await llm.plan(task, context)
        
        # Execute action (tool call)
        result = await execute_tool(action)
        
        # Update context
        context.append(result)
        
        # No maximum iteration limit!
        # No cost tracking!
        # No timeout!
```

**Triggers for infinite loops:**
- Ambiguous tasks that the agent can never "complete" to its satisfaction
- Tool results that always require "more information"
- Circular dependencies between tools
- Error handling that retries indefinitely

### Model Extraction Through Query Volume

Systematic querying to extract model knowledge or capabilities:

```python
# Extract the effective behavior of a fine-tuned model
# by querying it across a large input space
extracted_training_data = []

for prompt_template in prompt_templates:
    for variation in generate_variations(prompt_template):
        response = target_api.query(variation)
        extracted_training_data.append({
            'input': variation,
            'output': response
        })

# The attacker now has input-output pairs sufficient to
# train a clone of the target model
```

This constitutes:
- Intellectual property theft (model replication)
- Training data extraction (see #2)
- Massive API cost for the defender

### Variable-Length Input Abuse

Exploiting endpoints that accept variable-length inputs:

```python
# If the API charges per token and doesn't limit input size
payload = {
    "messages": [
        {"role": "user", "content": "x" * 1000000}  # 1M tokens
    ]
}
# Some APIs will process (and charge for) the full input before validating
```

### Agentic Amplification

Using the agent's tool-call capabilities to amplify resource consumption:

```
User: "Research this topic thoroughly"

Agent:
1. Web search (API call $0.01)
2. Read 20 web pages (20 × API call = $0.20)
3. Summarize each page (20 × LLM call = $0.60)
4. Cross-reference findings (LLM call $0.03)
5. Generate follow-up questions (LLM call $0.03)
6. Repeat steps 1-5 for each follow-up question (10 questions × $0.87 = $8.70)
7. Repeat step 6 for EACH new follow-up... 

Total after 3 levels of recursion: ~$750
Total after 5 levels: ~$50,000+
```

## Detection

### Cost Monitoring

1. **Real-time cost tracking per user/session:**
   ```python
   class CostTracker:
       def __init__(self, user_id: str):
           self.user_id = user_id
           self.session_cost = 0.0
           self.daily_cost = 0.0
           
       def record(self, input_tokens: int, output_tokens: int, model: str):
           cost = calculate_cost(input_tokens, output_tokens, model)
           self.session_cost += cost
           self.daily_cost += cost
           
           if self.session_cost > SESSION_LIMIT:
               raise CostLimitExceeded(f"Session limit exceeded: ${self.session_cost:.2f}")
           if self.daily_cost > DAILY_LIMIT:
               raise CostLimitExceeded(f"Daily limit exceeded: ${self.daily_cost:.2f}")
   ```

2. **Anomaly detection on spending patterns.** Alert when:
   - A user's consumption suddenly spikes
   - A single session's cost exceeds 10x the median
   - Overall API spending exceeds budget projections

### Request Analysis

1. **Input length monitoring.** Track input token counts per request and flag outliers.
2. **Output length monitoring.** Track output token generation and flag unusually long responses.
3. **Request frequency monitoring.** Detect automated query patterns (consistent timing, identical request structures).
4. **Tool call counting.** Track the number of tool calls per agent session and alert on excessive counts.

### Infrastructure Monitoring

1. **GPU/CPU utilization tracking** for self-hosted models.
2. **Memory usage monitoring** for context window accumulation.
3. **Queue depth monitoring** for request backlogs.
4. **Latency tracking** — sudden increases may indicate resource exhaustion.

## Mitigation

### Rate Limiting and Quotas

1. **Per-user rate limits:**
   ```python
   RATE_LIMITS = {
       'free_tier':     {'rpm': 10,  'tpd': 10000,   'cost_daily': 1.00},
       'basic_tier':    {'rpm': 60,  'tpd': 100000,  'cost_daily': 10.00},
       'premium_tier':  {'rpm': 300, 'tpd': 1000000, 'cost_daily': 100.00},
   }
   ```

2. **Per-request limits:**
   ```python
   MAX_INPUT_TOKENS = 8000       # Cap input size
   MAX_OUTPUT_TOKENS = 2000      # Cap output size
   MAX_TOOL_CALLS = 20           # Cap tool calls per session
   MAX_AGENT_ITERATIONS = 10     # Cap agent loop iterations
   REQUEST_TIMEOUT = 30          # seconds
   ```

3. **Budget caps with hard stops:**
   ```python
   async def process_request(request, user):
       # Check budget BEFORE processing
       if user.daily_spend >= user.daily_budget:
           return error("Daily budget exceeded. Resets at midnight UTC.")
       
       # Process with cost tracking
       response = await llm.generate(
           request,
           max_tokens=min(request.max_tokens, remaining_budget_tokens(user))
       )
       
       # Update spending
       user.daily_spend += calculate_cost(response)
       return response
   ```

### Agent Safeguards

1. **Iteration limits:**
   ```python
   async def safe_agent_loop(task: str, max_iterations: int = 15):
       for i in range(max_iterations):
           action = await agent.plan(task, context)
           
           if action.type == 'complete':
               return context.result
           
           result = await execute_tool(action)
           context.append(result)
       
       # Force completion after max iterations
       return await agent.summarize(context, 
           instruction="Provide the best answer with the information gathered so far.")
   ```

2. **Cost budgets per agent session:**
   ```python
   class BudgetedAgent:
       def __init__(self, budget_dollars: float = 5.0):
           self.budget = budget_dollars
           self.spent = 0.0
       
       async def execute_tool(self, tool_call):
           estimated_cost = estimate_tool_cost(tool_call)
           if self.spent + estimated_cost > self.budget:
               raise BudgetExhausted(
                   f"Agent budget exhausted (${self.spent:.2f}/${self.budget:.2f})")
           
           result = await tool_call.execute()
           self.spent += actual_cost(result)
           return result
   ```

3. **Recursion depth limits.** Prevent agent chains from spawning unbounded sub-agents.

### Input Validation

1. **Input size limits.** Reject requests that exceed maximum input token counts.
2. **Input complexity analysis.** Detect and reject prompts designed to maximize output:
   ```python
   EXPENSIVE_PATTERNS = [
       r'write.*\d{4,}.*words',           # "write 10000 words"
       r'translate.*every.*language',       # "translate to every language"
       r'list.*all.*\d{3,}',              # "list all 1000..."
       r'repeat.*\d{2,}.*times',          # "repeat 50 times"
   ]
   ```
3. **Semantic rate limiting.** Detect repeated semantically identical queries (possible extraction attack) even if the exact text varies.

### Infrastructure Protection

1. **Auto-scaling with budget limits.** Scale infrastructure to handle load, but cap maximum scale to prevent unbounded cost.
2. **Request queuing with priority.** Queue requests and process them by priority. During overload, drop low-priority requests.
3. **Circuit breakers.** Automatically disable endpoints when cost/error thresholds are breached:
   ```python
   class CircuitBreaker:
       def __init__(self, cost_threshold: float, window_seconds: int):
           self.threshold = cost_threshold
           self.window = window_seconds
           self.costs = []
       
       def check(self, cost: float) -> bool:
           now = time.time()
           self.costs = [(t, c) for t, c in self.costs if now - t < self.window]
           self.costs.append((now, cost))
           
           total = sum(c for _, c in self.costs)
           if total > self.threshold:
               raise CircuitOpen(f"Cost circuit breaker tripped: ${total:.2f} in {self.window}s")
           return True
   ```

4. **Alerting and kill switches.** Set up alerts at 50%, 75%, 90% of budget thresholds. Have manual kill switches for rapid shutdown.

### Anti-Extraction Measures

1. **Response diversity.** Add controlled variation to responses so systematic extraction produces inconsistent training data.
2. **Watermarking.** Embed statistical watermarks in model outputs that can identify extracted content.
3. **Query pattern detection.** Detect systematic querying patterns (grid searches, curriculum-like progressions) that indicate model extraction.
4. **Rate limits on unique queries.** Limit the number of unique queries per user per day.

## Key Takeaways

- LLM applications have an inverted cost model: the attacker's cost is near-zero while the defender's cost per request is significant. This makes financial DoS trivially easy.
- Agent architectures are particularly vulnerable to unbounded consumption through recursive tool-call loops. Always implement iteration limits, cost budgets, and timeouts.
- Rate limiting must operate at multiple levels: per-request (input/output size), per-session (tool calls, iterations), per-user (daily quotas), and per-system (budget caps, circuit breakers).
- Model extraction through systematic querying is both a theft risk and a consumption risk. Detect and rate-limit extraction patterns.
- Budget monitoring with hard stops is essential. An LLM application without spending caps is a liability waiting to be exploited.
- The best defense combines input validation (reject expensive requests), rate limiting (cap consumption per user), budget enforcement (hard spending limits), and monitoring (detect and alert on anomalies).

---

*This concludes the OWASP Top 10 for LLM Applications series. For the full series index, see [Series Introduction](00-series-introduction.md).*

## Series Conclusion

The ten vulnerabilities covered in this series represent the most critical security risks in LLM applications today. But they're not static — the threat landscape evolves as models become more capable, deployments become more complex, and adversaries develop new techniques.

What remains constant is the approach: understand the attack surface, implement defense in depth, monitor aggressively, and design for failure. Every LLM application will have vulnerabilities. The organizations that deploy AI safely are the ones that plan for that reality rather than pretending it doesn't exist.

The AI security community is still young. If this series was useful to you, share it with your team, red-team your own deployments, contribute to the OWASP LLM Top 10 project, and publish what you learn. The best defense is a well-informed ecosystem.

Stay paranoid. Ship secure.
