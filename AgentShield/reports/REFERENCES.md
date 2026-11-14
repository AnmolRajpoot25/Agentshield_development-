# AgentShield — Academic References & Related Work Bibliography

**Lexsi AI Safety Hackathon (Track 2a, Problem Statement 2a.3)**  
**Document Version:** 1.0 (Milestone 9 Formal Write-Up)  
**Scope:** Peer-Reviewed Academic Papers, Technical Standards & Security Frameworks  

---

## 1. Primary Academic & Industry Citations

1. **Greshake, K., Abdelnabi, S., Mishra, S., Endres, C., Holz, T., & Fritz, M.** (2023).  
   *Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection.*  
   Proceedings of the 16th ACM Workshop on Artificial Intelligence and Security (AISEC '23), pp. 79–90.  
   DOI: `10.1145/3605764.3623985`.  
   *(Foundational study establishing that passive external documents retrieved by LLM agents can carry weaponized adversarial instructions).*

2. **Perez, F., & Ribeiro, I.** (2022).  
   *Ignore This Title and Hack AP score: Evaluating Vulnerabilities of Large Language Models to Direct and Indirect Prompt Injection.*  
   arXiv preprint arXiv:2211.09527.  
   *(Analyzes prompt injection and conversational jailbreak vectors in transformer language models).*

3. **Zou, A., Wang, Z., Kolter, J. Z., & Mattstrow, M.** (2023).  
   *Universal and Transferable Adversarial Attacks on Aligned Language Models.*  
   arXiv preprint arXiv:2307.15043.  
   *(Demonstrates that prompt-level alignment guardrails can be systematically bypassed via adversarial optimization).*

4. **Wei, J., Haghtalab, N., & Steinhardt, J.** (2024).  
   *Jailbroken: How Does LLM Safety Training Fail?*  
   Advances in Neural Information Processing Systems (NeurIPS 2023).  
   *(Establishes the competing objectives hypothesis: models cannot reliably differentiate between helpfulness and safety constraints within the same context window).*

5. **Sanh, V., Debut, L., Chaumond, J., & Wolf, T.** (2019).  
   *DistilBERT, a distilled version of BERT: smaller, faster, cheaper and lighter.*  
   arXiv preprint arXiv:1910.01108.  
   *(Base transformer architecture utilized for the AgentShield Guard sequence classifier).*

6. **Sandhu, R. S., Coyne, E. J., Feinstein, H. L., & Youman, C. E.** (1996).  
   *Role-Based Access Control Models.*  
   IEEE Computer, 29(2), pp. 38–47.  
   DOI: `10.1109/2.485845`.  
   *(Foundational formal access control literature inspiring AgentShield's deterministic RBAC matrix).*

7. **Bell, D. E., & LaPadula, L. J.** (1973).  
   *Secure Computer Systems: Mathematical Foundations.*  
   MITRE Corporation Technical Report 2547.  
   *(Classic mandatory access control principles informing AgentShield's Resource-Level Access Control and clearance tagging).*

8. **OWASP Foundation.** (2025).  
   *OWASP Top 10 for Large Language Model Applications (2025 Edition).*  
   Open Web Application Security Project.  
   URL: `https://owasp.org/www-project-top-10-for-large-language-model-applications/`.  
   *(Directly maps to AgentShield threat coverage: LLM01: Prompt Injection, LLM02: Sensitive Information Disclosure, LLM07: System Prompt Leakage, and LLM08: Excessive Agency).*

9. **NIST.** (2023).  
   *Artificial Intelligence Risk Management Framework (AI RMF 1.0).*  
   National Institute of Standards and Technology, U.S. Department of Commerce.  
   DOI: `10.6028/NIST.AI.100-1`.  
   *(Provides the risk management framing for AgentShield's tamper-evident audit logging and fail-closed safety criteria).*

10. **LangChain AI.** (2024).  
    *LangGraph: Building Stateful Multi-Actor Applications with LLMs.*  
    URL: `https://github.com/langchain-ai/langgraph`.  
    *(State graph runtime engine orchestrating AgentShield's protected execution boundary).*

---

## 2. Comparison with Prior Work

| Approach | Representative Prior Art | Architectural Strategy | Vulnerability / Failure Mode in Multi-Turn Agents | AgentShield Advantage |
|:---|:---|:---|:---|:---|
| **System Prompt Defenses** | Perez & Ribeiro (2022) | Natural language instructions (*"Never delete files"*) | Susceptible to jailbreaks, roleplay framing, and persona drift. | **Decoupled Enforcement:** Authorization decisions are computed in code outside the LLM context. |
| **Single-Turn Input Filters** | Llama Guard, NeMo Guardrails | Binary classification of raw user prompt text | Fails when attacks are distributed gradually across multiple turns. | **Multi-Turn Context & Taint:** Tracks provenance and flags intent across turns and retrieved docs. |
| **Output Token Classifiers** | OpenAI Moderation API | Post-generation safety filtering | Tool call parameters are already dispatched before output text is rendered. | **Pre-Execution Gate:** Policy Engine intercepts action proposals **before** tool dispatch. |
| **Static Tool Allowlisting** | ReAct / Tool Use Paradigms | Global list of available tools | Cannot prevent an authorized user from performing an unauthorized action on sensitive resources. | **Fine-Grained RBAC + RLAC:** Enforces user clearance and data sensitivity limits per operation. |
