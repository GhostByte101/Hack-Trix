#include <iostream>
#include <string>
using namespace std;

const int MAX_SYSTEMS = 5; // Total systems in the network
const int MAX_QUEUE = 10;  // Max number of attacks that can be queued

// Represent a single system (node)
struct SystemNode
{
    string name;
    string ip;
    bool compromised;
    double vuln;  // 0.0 .. 1.0 (higher = easier to exploit)
    bool patched; // reduces vuln by factor, to make it harder to compromise
};

// Represent a simple manual queue
struct AttackQueue
{
    string queue[MAX_QUEUE]; // saves upto max 10 attack to nodes
    int front;
    int rear;
    int count;
};

void initQueue(AttackQueue &q)
{ // simple function to initialize a queue of type attack queue
    q.front = 0;
    q.rear = -1;
    q.count = 0;
}

bool isEmpty(AttackQueue &q)
{
    return q.count == 0;
}

bool isFull(AttackQueue &q)
{
    return q.count == MAX_QUEUE;
}

void enqueue(AttackQueue &q, string attack)
{
    if (isFull(q))
    {
        cout << "[!] Attack queue is full! Cannot add more.\n";
        return;
    }
    q.rear = (q.rear + 1);
    q.queue[q.rear] = attack;
    q.count++;
    cout << "[+] Attack added to queue: " << attack << endl;
}

string dequeue(AttackQueue &q)
{
    if (isEmpty(q))
    {

        return ""; // return empty string to indicate none
    }
    string attack = q.queue[q.front];
    q.front = (q.front + 1);
    q.count--;
    return attack;
}

void setupNetwork(SystemNode systems[], int &count)
{
    count = MAX_SYSTEMS;

    // name,          ip,    compromised, vuln, patched

    systems[0] = {"Main Server", "192.168.0.1", false, 0.30, false};   // fairly secure
    systems[1] = {"Admin PC", "192.168.0.2", false, 0.45, true};       // patched
    systems[2] = {"Database", "192.168.0.3", false, 0.85, false};      // high vuln
    systems[3] = {"Firewall", "192.168.0.4", false, 0.20, true};       // patched, low vuln
    systems[4] = {"Backup Server", "192.168.0.5", false, 0.55, false}; // medium vuln
}

void showNetwork(SystemNode systems[], int count)
{
    cout << "\n=== SYSTEM STATUS ===\n";
    for (int i = 0; i < count; i++)
    {
        cout << systems[i].name << " (" << systems[i].ip << ") - ";
        if (systems[i].compromised)
            cout << "[COMPROMISED]";
        else
            cout << "[SECURE]";
        cout << "  vuln=" << systems[i].vuln;
        if (systems[i].patched)
            cout << " [PATCHED]";
        cout << "\n";
    }
    cout << endl;
}

// Deterministic exploit: success if effectiveVuln (eff) >= threshold
bool attemptExploit(SystemNode &s)
{
    double eff = s.vuln;
    if (s.patched)
    {
        eff = eff * 0.4; // patch reduces exploitability
    }
    const double THRESH = 0.6; // can change the vuln value to make it easier to exploit
    return eff >= THRESH;
}

// Process an attack from the queue: lookup IP and attempt exploit

void processAttack(SystemNode systems[], int count, string ip)
{

    if (ip == "")
    {
        cout << "[!] No attack to process.\n";
        return;
    }

    for (int i = 0; i < count; i++)
    {
        if (systems[i].ip == ip)
        {
            if (systems[i].compromised)
            {
                cout << "[i] " << systems[i].name << " is already compromised.\n";
                return;
            }
            bool success = attemptExploit(systems[i]);
            if (success)
            {
                systems[i].compromised = true;
                cout << "[!] ALERT: " << systems[i].name << " (" << systems[i].ip << ") has been hacked!\n";
            }
            else
            {
                cout << "[x] Exploit failed on " << systems[i].name << " (" << systems[i].ip << ").\n";
                cout << "    Effective vuln < threshold. (eff=" << (systems[i].patched ? systems[i].vuln * 0.4 : systems[i].vuln) << ")\n";
            }
            return;
        }
    }
    cout << "[x] No system with IP: " << ip << endl;
}

int main()
{
    SystemNode systems[MAX_SYSTEMS];
    int systemCount = 0;
    AttackQueue attackQueue;

    setupNetwork(systems, systemCount);
    initQueue(attackQueue);

    int choice;
    string targetIP;

    cout << "=== CYBER RANGE GAME — PHASE 1 (with vuln) ===\n";
    cout << "Simulated network defense environment\n\n";

    while (true)
    {
        cout << "1. View network status\n";
        cout << "2. Add attack to queue\n";
        cout << "3. Process next attack\n";
        cout << "4. Exit\n";
        cout << "Enter choice: ";

        cin>>choice;

        if (!(cin >> choice)) //error checking, if something other than int is entered
            break;

        switch (choice)
        {
        case 1:
            showNetwork(systems, systemCount);
            break;

        case 2:
            cout << "Enter target IP to attack: ";
            cin >> targetIP;
            enqueue(attackQueue, targetIP);
            break;

        case 3:
        {
            if (isEmpty(attackQueue))
            {
                cout << "[!] No attacks to process.\n";
            }
            else
            {
                string ip = dequeue(attackQueue);
                processAttack(systems, systemCount, ip);
            }
            break;
        }

        case 4:
            cout << "Exiting game. Goodbye!\n";
            return 0;

        default:
            cout << "[x] Invalid choice. Try again.\n";
        }
        cout << endl;
    }
    return 0;
}
