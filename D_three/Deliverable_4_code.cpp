#include <iostream>
#include <string>
using namespace std;

const int MAX_SYSTEMS = 10;
const int ATTACK_QUEUE_SIZE = 30;
const double EXPLOIT_THRESHOLD = 0.6;

struct SysData
{
    int id;
    string name;
    string ip;
    bool compromised;
    double vuln;
    bool patched;
};

struct SysNode
{
    SysData data;
    SysNode *prev;
    SysNode *next;
};

struct SysList
{
    SysNode *head;
    SysNode *tail;
    int size;
};

void initSysList(SysList &list)
{
    list.head = nullptr;
    list.tail = nullptr;
    list.size = 0;
}

void appendSystem(SysList &list, const SysData &d)
{
    SysNode *node = new SysNode();
    node->data = d;
    node->data.id = list.size;
    node->prev = nullptr;
    node->next = nullptr;
    if (list.tail == nullptr)
    {
        list.head = list.tail = node;
    }
    else
    {
        node->prev = list.tail;
        list.tail->next = node;
        list.tail = node;
    }
    list.size++;
}

SysNode *findSystemByIP(SysList &list, const string &ip)
{
    SysNode *cur = list.head;
    while (cur)
    {
        if (cur->data.ip == ip)
            return cur;
        cur = cur->next;
    }
    return nullptr;
}

// find by id
SysNode *findSystemById(SysList &list, int id)
{
    SysNode *cur = list.head;
    while (cur)
    {
        if (cur->data.id == id)
            return cur;
        cur = cur->next;
    }
    return nullptr;
}

void showSystems(SysList &list)
{
    cout << "\n--- Systems (" << list.size << ") ---\n";
    SysNode *cur = list.head;
    while (cur)
    {
        cout << cur->data.id << ": " << cur->data.name << " (" << cur->data.ip << ") ";
        cout << (cur->data.compromised ? "[COMP]" : "[SECURE]");
        cout << " vuln=" << cur->data.vuln;
        if (cur->data.patched)
            cout << " [PATCHED]";
        cout << "\n";
        cur = cur->next;
    }
    if (list.size == 0)
        cout << "No systems.\n";
    cout << "----------------------\n";
}

void clearSysList(SysList &list)
{
    SysNode *cur = list.head;
    while (cur)
    {
        SysNode *nx = cur->next;
        delete cur;
        cur = nx;
    }
    list.head = list.tail = nullptr;
    list.size = 0;
}

struct LogNode
{
    string msg;
    LogNode *next;
};

struct LogList
{
    LogNode *head;
    LogNode *tail;
};

void initLogList(LogList &l) { l.head = l.tail = nullptr; }
void appendLog(LogList &l, const string &m)
{
    LogNode *n = new LogNode();
    n->msg = m;
    n->next = nullptr;
    if (l.tail == nullptr)
        l.head = l.tail = n;
    else
    {
        l.tail->next = n;
        l.tail = n;
    }
}
void showLogs(LogList &l)
{
    cout << "\n--- Event Logs ---\n";
    LogNode *cur = l.head;
    int i = 1;
    while (cur)
    {
        cout << i << ". " << cur->msg << "\n";
        cur = cur->next;
        ++i;
    }
    if (i == 1)
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
    SysNode *s;
    ScanNode *next;
};

struct Scanner
{
    ScanNode *cur;
};

void initScanner(Scanner &sc) { sc.cur = nullptr; }

void buildScannerFromSysList(Scanner &sc, SysList &list)
{

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
    if (!list.head)
        return;
    SysNode *it = list.head;
    ScanNode *first = nullptr;
    ScanNode *prev = nullptr;
    while (it)
    {
        ScanNode *sn = new ScanNode();
        sn->s = it;
        sn->next = nullptr;
        if (!first)
            first = sn;
        if (prev)
            prev->next = sn;
        prev = sn;
        it = it->next;
    }
    if (prev && first)
    {
        prev->next = first;
        sc.cur = first;
    }
}

SysNode *scannerNext(Scanner &sc)
{
    if (!sc.cur)
        return nullptr;
    SysNode *res = sc.cur->s;
    sc.cur = sc.cur->next;
    return res;
}

struct Action
{
    int sysId;
    bool prev;
    Action *next;
};

struct UndoStack
{
    Action *top;
};

void initUndo(UndoStack &st) { st.top = nullptr; }
void pushUndo(UndoStack &st, int id, bool prevState)
{
    Action *a = new Action();
    a->sysId = id;
    a->prev = prevState;
    a->next = st.top;
    st.top = a;
}
bool popUndo(UndoStack &st, int &outId, bool &outPrev)
{
    if (!st.top)
        return false;
    Action *t = st.top;
    outId = t->sysId;
    outPrev = t->prev;
    st.top = t->next;
    delete t;
    return true;
}
void clearUndo(UndoStack &st)
{
    int id;
    bool p;
    while (popUndo(st, id, p))
    {
    }
}

struct AttackQueue
{
    string items[ATTACK_QUEUE_SIZE];
    int front;
    int rear;
    int count;
};

void initAttackQ(AttackQueue &q)
{
    q.front = 0;
    q.rear = -1;
    q.count = 0;
}
bool attackQEmpty(AttackQueue &q) { return q.count == 0; }
bool attackQFull(AttackQueue &q) { return q.count == ATTACK_QUEUE_SIZE; }
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
void showAttackQ(AttackQueue &q)
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
    Graph()
    {
        for (int i = 0; i < MAX_SYSTEMS; ++i)
            for (int j = 0; j < MAX_SYSTEMS; ++j)
                adj[i][j] = false;
    }
    void addEdge(int u, int v)
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
        adj[u][v] = adj[v][u] = false;
    }
    void show(int upto)
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

    bool bfs(int s, int t, int upto, int parent[])
    {
        if (s < 0 || t < 0 || s >= upto || t >= upto)
            return false;
        bool visited[MAX_SYSTEMS];
        for (int i = 0; i < MAX_SYSTEMS; ++i)
            visited[i] = false, parent[i] = -1;
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

bool attemptExploit(SysData &s)
{
    double eff = s.vuln;
    if (s.patched)
        eff *= 0.4;
    return (eff >= EXPLOIT_THRESHOLD);
}

void seedDefaultNetwork(SysList &systems, Graph &graph)
{

    SysData a;
    a.name = "Main Server";
    a.ip = "192.168.0.1";
    a.compromised = false;
    a.vuln = 0.30;
    a.patched = false;
    SysData b;
    b.name = "Admin PC";
    a.compromised = false;
    b.ip = "192.168.0.2";
    b.vuln = 0.45;
    b.patched = true;
    SysData c;
    c.name = "Database";
    c.ip = "192.168.0.3";
    c.compromised = false;
    c.vuln = 0.85;
    c.patched = false;
    SysData d;
    d.name = "Firewall";
    d.ip = "192.168.0.4";
    d.compromised = false;
    d.vuln = 0.20;
    d.patched = true;
    SysData e;
    e.name = "Backup";
    e.ip = "192.168.0.5";
    e.compromised = false;
    e.vuln = 0.55;
    e.patched = false;

    appendSystem(systems, a);
    appendSystem(systems, b);
    appendSystem(systems, c);
    appendSystem(systems, d);
    appendSystem(systems, e);

    graph.addEdge(0, 1); // Main-Admin
    graph.addEdge(1, 2); // Admin-Database
    graph.addEdge(0, 3); // Main-Firewall
    graph.addEdge(3, 4); // Firewall-Backup
    graph.addEdge(2, 4); // Database-Backup
}

void attemptSpread(SysNode *node, SysList &systems, Graph &graph, LogList &logs, UndoStack &undo)
{
    if (!node)
        return;
    int u = node->data.id;
    for (int v = 0; v < systems.size; ++v)
    {
        if (graph.adj[u][v])
        {
            SysNode *neigh = findSystemById(systems, v);
            if (!neigh)
                continue;
            if (!neigh->data.compromised)
            {
                // push undo for neighbor
                pushUndo(undo, neigh->data.id, neigh->data.compromised);
                // attempt exploit on neighbor
                if (attemptExploit(neigh->data))
                {
                    neigh->data.compromised = true;
                    string msg = "SPREAD: " + neigh->data.name + " compromised from " + node->data.ip;
                    appendLog(logs, msg);
                    cout << "[>] " << msg << "\n";
                }
                else
                {
                    string msg = "SPREAD-FAIL: " + neigh->data.name + " resisted spread from " + node->data.ip;
                    appendLog(logs, msg);
                }
            }
        }
    }
}

void processNextAttack(AttackQueue &aq, SysList &systems, Graph &graph, LogList &logs, UndoStack &undo)
{
    if (attackQEmpty(aq))
    {
        cout << "[!] No attacks in queue.\n";
        return;
    }
    string ip = attackDequeue(aq);
    cout << "[*] Processing attack -> " << ip << "\n";
    SysNode *target = findSystemByIP(systems, ip);
    if (!target)
    {
        cout << "[x] Target IP not found in network.\n";
        appendLog(logs, "Attack on unknown IP: " + ip);
        return;
    }

    pushUndo(undo, target->data.id, target->data.compromised);

    if (attemptExploit(target->data))
    {
        target->data.compromised = true;
        string msg = "BREACH: " + target->data.name + " (" + target->data.ip + ")";
        cout << "[!!!] " << msg << "\n";
        appendLog(logs, msg);

        attemptSpread(target, systems, graph, logs, undo);
    }
    else
    {
        string msg = "Exploit failed on " + target->data.name + " (" + target->data.ip + ")";
        cout << "[x] " << msg << "\n";
        appendLog(logs, msg);
    }
}

void doUndo(UndoStack &undo, SysList &systems, LogList &logs)
{
    int id;
    bool prev;
    if (!popUndo(undo, id, prev))
    {
        cout << "[!] Nothing to undo.\n";
        return;
    }
    SysNode *node = findSystemById(systems, id);
    if (!node)
    {
        cout << "[!] Undo target not found (id=" << id << ")\n";
        return;
    }
    node->data.compromised = prev;
    string msg = "UNDO: restored " + node->data.name + " (" + node->data.ip + ") to " + (prev ? "COMPROMISED" : "SECURE");
    appendLog(logs, msg);
    cout << msg << "\n";
}

void printPathIds(SysList &systems, int parent[])
{
}

int main()
{
    cout << "=== Hack Trix (simplified) ===\n";

    SysList systems;
    initSysList(systems);
    Graph graph;
    LogList logs;
    initLogList(logs);
    Scanner scanner;
    initScanner(scanner);
    UndoStack undo;
    initUndo(undo);
    AttackQueue attackQ;
    initAttackQ(attackQ);

    // seed
    seedDefaultNetwork(systems, graph);
    buildScannerFromSysList(scanner, systems);

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
        cout << "8) Show graph (adj matrix)\n";
        cout << "9) Add/remove connection\n";
        cout << "10) Find path (BFS) between two IPs\n";
        cout << "11) Exit\n";
        cout << "Choose: ";
        int choice;
        if (!(cin >> choice))
            break;

        if (choice == 1)
        {
            showSystems(systems);
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
            processNextAttack(attackQ, systems, graph, logs, undo);
        }
        else if (choice == 6)
        {
            doUndo(undo, systems, logs);
        }
        else if (choice == 7)
        {
            SysNode *s = scannerNext(scanner);
            if (!s)
                cout << "[!] No systems to scan.\n";
            else
            {
                cout << "[*] Scanner visiting: " << s->data.name << " (" << s->data.ip << ") - " << (s->data.compromised ? "COMPROMISED" : "SECURE") << "\n";
                if (!s->data.compromised && s->data.vuln >= 0.8)
                {
                    appendLog(logs, "Scanner: high vuln detected on " + s->data.ip);
                    cout << "[!] High vulnerability detected.\n";
                }
            }
        }
        else if (choice == 8)
        {
            graph.show(systems.size);
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
            SysNode *na = findSystemByIP(systems, a);
            SysNode *nb = findSystemByIP(systems, b);
            if (!na || !nb)
            {
                cout << "[x] One or both IPs not found.\n";
            }
            else
            {
                if (sub == 1)
                {
                    graph.addEdge(na->data.id, nb->data.id);
                    cout << "[+] Edge added.\n";
                }
                else
                {
                    graph.removeEdge(na->data.id, nb->data.id);
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
            SysNode *na = findSystemByIP(systems, a);
            SysNode *nb = findSystemByIP(systems, b);
            if (!na || !nb)
            {
                cout << "[x] One or both IPs not found.\n";
            }
            else
            {
                int parent[MAX_SYSTEMS];
                for (int i = 0; i < MAX_SYSTEMS; ++i)
                    parent[i] = -1;
                bool ok = graph.bfs(na->data.id, nb->data.id, systems.size, parent);
                if (!ok)
                    cout << "[!] No path found.\n";
                else
                {
                    // rebuild path
                    int path[MAX_SYSTEMS];
                    int plen = 0;
                    int cur = nb->data.id;
                    while (cur != -1)
                    {
                        path[plen++] = cur;
                        cur = parent[cur];
                    }
                    cout << "Path: ";
                    for (int i = plen - 1; i >= 0; --i)
                    {
                        SysNode *node = findSystemById(systems, path[i]);
                        cout << node->data.ip;
                        if (i)
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
    clearSysList(systems);
    return 0;
}