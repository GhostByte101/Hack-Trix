#include <iostream>
#include <string>
using namespace std;

const int MAX_SYSTEMS = 10;
const int ATTACK_QUEUE_SIZE = 30;
const double EXPLOIT_THRESHOLD = 0.6;

struct System
{
    int id;
    string name;
    string ip;
    bool compromised;
    double vuln;
    bool patched;

    System *next;
    System *prev;
};

System *head = nullptr;
System *tail = nullptr;
int systemCount = 0;

void appendSystem(const System &d)
{
    System *node = new System(d);

    node->id = systemCount;
    node->next = nullptr;
    node->prev = tail;

    if (head == nullptr)
    {
        head = tail = node;
    }
    else
    {
        tail->next = node;
        tail = node;
    }

    systemCount++;
}

void showSystems()
{
    System *cur = head;
    while (cur)
    {
        cout << cur->id << ": " << cur->name
             << " (" << cur->ip << ")\n";
        cur = cur->next;
    }
}

System *findSystemByIP(const string &ip)
{
    System *cur = head;
    while (cur)
    {
        if (cur->ip == ip)
            return cur;
        cur = cur->next;
    }
    return nullptr;
}

System *findSystemById(int id)
{
    System *cur = head;
    while (cur)
    {
        if (cur->id == id)
            return cur;
        cur = cur->next;
    }
    return nullptr;
}

void clearSystems()
{
    System *cur = head;
    while (cur)
    {
        System *nx = cur->next;
        delete cur;
        cur = nx;
    }

    head = nullptr;
    tail = nullptr;
    systemCount = 0;
}

struct LogNode
{
    string msg;
    LogNode *next;

    LogNode(const string &m) : msg(m)
    {
        next = nullptr;
    }
};

struct LogList
{
    LogNode *head;
    LogNode *tail;

    LogList()
    {
        head = nullptr;
        tail = nullptr;
    }
};

void appendLog(LogList &l, const string &m)
{
    LogNode *node = new LogNode(m);

    if (l.tail == nullptr)
    {
        // list empty
        l.head = l.tail = node;
    }
    else
    {
        l.tail->next = node;
        l.tail = node;
    }
}

void showLogs(const LogList &l)
{
    cout << "\n--- Event Logs ---\n";
    const LogNode *cur = l.head;
    int i = 1;

    while (cur) // if cur is pounting to nullpte, while wont run
    {
        cout << i << ". " << cur->msg << "\n";
        cur = cur->next;
        i++;
    }

    if (i == 1) // if while does not run, we have the linked list as empty
        cout << "No logs yet.\n";

    cout << "------------------\n";
}

void clearLogs(LogList &l)
{
    LogNode *cur = l.head;

    while (cur)
    {
        LogNode *nx = cur->next;
        delete cur;
        cur = nx;
    }

    l.head = l.tail = nullptr;
}

struct ScanNode
{
    System *s;
    ScanNode *next;

    ScanNode(System *sys) : s(sys), next(nullptr) {}
};

struct Scanner
{
    ScanNode *cur = nullptr;
};

void buildScannerFromSystemList(Scanner &sc)
{
    // If scanner already has nodes, delete the circular list
    if (sc.cur)
    {
        ScanNode *start = sc.cur;
        ScanNode *it = sc.cur->next;

        while (it != start)
        {
            ScanNode *nx = it->next;
            delete it;
            it = nx;
        }
        delete start;
        sc.cur = nullptr;
    }

    if (!head) // head is the global pointer to the system list
        return;

    System *it = head;
    ScanNode *first = nullptr;
    ScanNode *before = nullptr;

    while (it)
    {
        ScanNode *sn = new ScanNode(it);

        if (!first)
            first = sn;

        if (before)
            before->next = sn;

        before = sn;
        it = it->next;
    }

    // Make the list circular and set scanner's current pointer
    if (before && first)
    {
        before->next = first;
        sc.cur = first;
    }
}

System *scannerNext(Scanner &sc)
{
    if (!sc.cur)
        return nullptr;
    System *res = sc.cur->s;
    sc.cur = sc.cur->next;
    return res;
}

struct Action
{
    int systemId;
    bool previousState;
    Action *next;
}; // Action*top;

struct UndoStack
{
    Action *top;
};

void initUndo(UndoStack &st)
{
    st.top = nullptr;
}

void pushUndo(UndoStack &st, int id, bool prevState)
{
    Action *a = new Action();
    a->systemId = id;
    a->previousState = prevState;
    a->next = st.top;
    st.top = a;
}

bool popUndo(UndoStack &st, int &outId, bool &outPrev)
{
    if (!st.top)
        return false;

    Action *t = st.top;
    outId = t->systemId;
    outPrev = t->previousState;

    st.top = t->next;
    delete t;

    return true;
}

void clearUndo(UndoStack &st)
{
    int id;
    bool prev;

    while (popUndo(st, id, prev))
    {
        // popUndo already deletes the node
    }
}

struct AttackQueue
{
    string items[ATTACK_QUEUE_SIZE];
    int front;
    int rear;
    int count;

    AttackQueue()
    {
        front = 0;
        rear = -1;
        count = 0;
    }
};

bool attackQEmpty(const AttackQueue &q)
{
    return q.count == 0;
}

bool attackQFull(const AttackQueue &q)
{
    return q.count == ATTACK_QUEUE_SIZE;
}

void attackEnqueue(AttackQueue &q, const string &ip)
{
    if (attackQFull(q))
    {
        cout << "[!] Attack queue is full!\n";
        return;
    }

    q.rear = (q.rear + 1) % ATTACK_QUEUE_SIZE;
    q.items[q.rear] = ip;
    q.count++;

    cout << "[+] Enqueued attack -> " << ip << "\n";
}

string attackDequeue(AttackQueue &q)
{
    if (attackQEmpty(q))
        return "";

    string ip = q.items[q.front];
    q.front = (q.front + 1) % ATTACK_QUEUE_SIZE;
    q.count--;

    return ip;
}

void showAttackQ(const AttackQueue &q)
{
    cout << "\n--- Attack Queue (" << q.count << ") ---\n";

    if (q.count == 0)
    {
        cout << "Empty\n-------------------------\n";
        return;
    }

    for (int i = 0; i < q.count; ++i)
    {
        int idx = (q.front + i) % ATTACK_QUEUE_SIZE;
        cout << i + 1 << ". " << q.items[idx] << "\n";
    }

    cout << "-------------------------\n";
}

struct Graph
{
    bool adj[MAX_SYSTEMS][MAX_SYSTEMS];

   
    Graph()  // constructor making
    {
        for (int i = 0; i < MAX_SYSTEMS; ++i)
            for (int j = 0; j < MAX_SYSTEMS; ++j)
                adj[i][j] = false;
    }

    void addEdge(int u, int v) // u and v are indexes
    {
        if (u < 0 || v < 0 || u >= MAX_SYSTEMS || v >= MAX_SYSTEMS)
            return;

        adj[u][v] = true;
        adj[v][u] = true;
    }

    void removeEdge(int u, int v)
    {
        if (u < 0 || v < 0 || u >= MAX_SYSTEMS || v >= MAX_SYSTEMS)
            return;

        adj[u][v] = false;
        adj[v][u] = false;
    }

    void show(int upto) const
    {
        cout << "\n--- Adjacency Matrix ---\n";
        for (int i = 0; i < upto; ++i)
        {
            for (int j = 0; j < upto; ++j)
                cout << (adj[i][j] ? "1 " : "0 ");
            cout << "\n";
        }
        cout << "------------------------\n";
    }

    bool bfs(int s, int t, int upto, int parent[]) // s = start, t= target, upto = systemCount, parent array stores the connections
    {
        if (s < 0 || t < 0 || s >= upto || t >= upto)
            return false;

        bool visited[MAX_SYSTEMS];
        for (int i = 0; i < MAX_SYSTEMS; ++i)
        {
            visited[i] = false;
            parent[i] = -1;
        }

        int q[MAX_SYSTEMS];
        int qf = 0, qr = 0;

        q[qr++] = s;
        visited[s] = true;
        parent[s] = -1;

        while (qf < qr)
        {
            int u = q[qf++];

            if (u == t)
                return true;

            for (int v = 0; v < upto; ++v)
            {
                if (adj[u][v] && !visited[v])
                {
                    visited[v] = true;
                    parent[v] = u;
                    q[qr++] = v;
                }
            }
        }

        return false;
    }
};

bool attemptExploit(const System &sys)
{
    double effective = sys.vuln;

    if (sys.patched)
        effective *= 0.4;

    return (effective >= EXPLOIT_THRESHOLD);
}

void seedDefaultNetwork(Graph &graph)
{
    System a;
    a.name = "Main Server";
    a.ip = "192.168.0.1";
    a.compromised = false;
    a.vuln = 0.30;
    a.patched = false;

    System b;
    b.name = "Admin PC";
    b.ip = "192.168.0.2";
    b.compromised = false;
    b.vuln = 0.45;
    b.patched = true;

    System c;
    c.name = "Database";
    c.ip = "192.168.0.3";
    c.compromised = false;
    c.vuln = 0.85;
    c.patched = false;

    System d;
    d.name = "Firewall";
    d.ip = "192.168.0.4";
    d.compromised = false;
    d.vuln = 0.7;
    d.patched = true;

    System e;
    e.name = "Backup";
    e.ip = "192.168.0.5";
    e.compromised = false;
    e.vuln = 0.99;
    e.patched = false;

    System f;
    f.name = "Laptop";
    f.ip = "192.168.0.6";
    f.compromised = true;
    f.vuln = 1.00;
    f.patched = false;

    appendSystem(a);
    appendSystem(b);
    appendSystem(c);
    appendSystem(d);
    appendSystem(e);
    appendSystem(f);

    graph.addEdge(0, 1); // Main --- Admin
    graph.addEdge(1, 2); // Admin --- Database
    graph.addEdge(0, 3); // Main --- Firewall
    graph.addEdge(0, 4); // Main --- Backup
    graph.addEdge(2, 4); // Database --- Backup
    graph.addEdge(0, 5); // Main --- Laptop
}

void attemptSpread(System *node, Graph &graph, LogList &logs, UndoStack &undo)
{
    if (!node)
        return;

    int u = node->id;

    for (int v = 0; v < systemCount; ++v)
    {
        if (graph.adj[u][v])
        {
            System *neigh = findSystemById(v);
            if (!neigh)
                continue;

            if (!neigh->compromised)
            {
                // Save undo info
                pushUndo(undo, neigh->id, neigh->compromised);

                // Attempt exploit
                if (attemptExploit(*neigh))
                {
                    neigh->compromised = true;

                    string msg =
                        "SPREAD: " + neigh->name +
                        " compromised from " + node->ip;

                    appendLog(logs, msg);
                    cout << "[>] " << msg << "\n";
                }
                else
                {
                    string msg =
                        "SPREAD-FAIL: " + neigh->name +
                        " resisted spread from " + node->ip;

                    appendLog(logs, msg);
                }
            }
        }
    }
}

void processNextAttack(AttackQueue &aq, Graph &graph, LogList &logs, UndoStack &undo)
{
    // Queue empty
    if (attackQEmpty(aq))
    {
        cout << "[!] No attacks in queue.\n";
        return;
    }

    // Dequeue next attack
    string ip = attackDequeue(aq);
    cout << "[*] Processing attack -> " << ip << "\n";

    // Find target system
    System *target = findSystemByIP(ip);
    if (!target)
    {
        cout << "[x] Target IP not found in network.\n";
        appendLog(logs, "Attack on unknown IP: " + ip);
        return;
    }

    // Save previous state for UNDO
    pushUndo(undo, target->id, target->compromised);

    // Attempt exploit
    if (attemptExploit(*target))
    {
        target->compromised = true;

        string msg = "BREACH: " + target->name +
                     " (" + target->ip + ")";
        cout << "[!!!] " << msg << "\n";
        appendLog(logs, msg);

        // Attempt lateral movement
        attemptSpread(target, graph, logs, undo);
    }
    else
    {
        string msg = "Exploit failed on " + target->name +
                     " (" + target->ip + ")";
        cout << "[x] " << msg << "\n";
        appendLog(logs, msg);
    }
}

void doUndo(UndoStack &undo, LogList &logs)
{
    int id;
    bool prev;

    // Nothing to undo
    if (!popUndo(undo, id, prev))
    {
        cout << "[!] Nothing to undo.\n";
        return;
    }

    // Locate system by ID
    System *node = findSystemById(id);
    if (!node)
    {
        cout << "[!] Undo target not found (id = " << id << ")\n";
        return;
    }

    // Restore previous compromised state
    node->compromised = prev;

    // Prepare log message
    string msg = "UNDO: Restored " + node->name +
                 " (" + node->ip + ") to " +
                 (prev ? "COMPROMISED" : "SECURE");

    appendLog(logs, msg);
    cout << msg << "\n";
}

int main()
{
    cout << "=== Hack Trix ===\n";

    LogList logs;
    Scanner scanner;
    UndoStack undo;
    initUndo(undo);
    AttackQueue attackQ;
    Graph graph;

    // Seed default network
    seedDefaultNetwork(graph);
    buildScannerFromSystemList(scanner);

    while (true)
    {
        cout << "\nMain Menu:\n";
        cout << "1) Show systems\n";
        cout << "2) Show logs\n";
        cout << "3) Enqueue attack (IP)\n";
        cout << "4) Show attack queue\n";
        cout << "5) Process next attack\n";
        cout << "6) Undo last action\n";
        cout << "7) Run scanner (next)\n";
        cout << "8) Show graph (adjacency matrix)\n";
        cout << "9) Add/remove connection\n";
        cout << "10) Find path (BFS) between two IPs\n";
        cout << "11) Exit\n";
        cout << "Choose: ";
        int choice;
        if (!(cin >> choice))
            break;

        if (choice == 1)
        {
            showSystems();
        }
        else if (choice == 2)
        {
            showLogs(logs);
        }
        else if (choice == 3)
        {
            cout << "Enter target IP to enqueue: ";
            string ip;
            cin >> ip;
            attackEnqueue(attackQ, ip);
        }
        else if (choice == 4)
        {
            showAttackQ(attackQ);
        }
        else if (choice == 5)
        {
            processNextAttack(attackQ, graph, logs, undo);
        }
        else if (choice == 6)
        {
            doUndo(undo, logs);
        }
        else if (choice == 7)
        {
            System *s = scannerNext(scanner);
            if (!s)
                cout << "[!] No systems to scan.\n";
            else
            {
                cout << "[*] Scanner visiting: " << s->name << " (" << s->ip << ") - "
                     << (s->compromised ? "COMPROMISED" : "SECURE") << "\n";

                if (!s->compromised && s->vuln >= 0.8)
                {
                    appendLog(logs, "Scanner: high vuln detected on " + s->ip);
                    cout << "[!] High vulnerability detected.\n";
                }
            }
        }
        else if (choice == 8)
        {
            graph.show(systemCount);
        }
        else if (choice == 9)
        {
            cout << "1) Add connection  2) Remove connection : ";
            int sub;
            cin >> sub;
            cout << "Enter first IP: ";
            string a;
            cin >> a;
            cout << "Enter second IP: ";
            string b;
            cin >> b;
            System *na = findSystemByIP(a);
            System *nb = findSystemByIP(b);
            if (!na || !nb)
            {
                cout << "[x] One or both IPs not found.\n";
            }
            else
            {
                if (sub == 1)
                {
                    graph.addEdge(na->id, nb->id);
                    cout << "[+] Edge added.\n";
                }
                else
                {
                    graph.removeEdge(na->id, nb->id);
                    cout << "[-] Edge removed.\n";
                }
            }
        }
        else if (choice == 10)
        {
            cout << "Enter source IP: ";
            string a;
            cin >> a;
            cout << "Enter target IP: ";
            string b;
            cin >> b;
            System *na = findSystemByIP(a);
            System *nb = findSystemByIP(b);
            if (!na || !nb)
            {
                cout << "[x] One or both IPs not found.\n";
            }
            else
            {
                int parent[MAX_SYSTEMS];
                bool ok = graph.bfs(na->id, nb->id, systemCount, parent);
                if (!ok)
                    cout << "[!] No path found.\n";
                else
                {
                    // Rebuild path
                    int path[MAX_SYSTEMS];
                    int plen = 0;
                    int cur = nb->id;
                    while (cur != -1)
                    {
                        path[plen++] = cur;
                        cur = parent[cur];
                    }

                    cout << "Path: ";
                    for (int i = plen - 1; i >= 0; --i)
                    {
                        System *node = findSystemById(path[i]);
                        cout << node->ip;
                        if (i > 0)
                            cout << " -> ";
                    }
                    cout << "\n";
                }
            }
        }
        else if (choice == 11)
        {
            cout << "Exiting. Bye!\n";
            break;
        }
        else
        {
            cout << "[x] Invalid option.\n";
        }
    }

    clearUndo(undo);
    clearLogs(logs);

    // Cleanup scanner circular list
    if (scanner.cur)
    {
        ScanNode *start = scanner.cur;
        ScanNode *it = scanner.cur->next;
        while (it != start)
        {
            ScanNode *nx = it->next;
            delete it;
            it = nx;
        }
        delete start;
        scanner.cur = nullptr;
    }

    clearSystems();
    return 0;
}
