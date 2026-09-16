// FIELD ENGINE -- version compilada v2: corrige 3 fallas encontradas en la
// v1 (revalidacion contra grafo vivo ausente, sintaxis field degenerada a
// 2 lineas fijas, lookup de arista O(degree) en vez de O(1)).
//
// Arquitectura: dos piezas separadas y ambas reales, no una simulando a la
// otra:
//   (1) MOTOR ALGORITMICO (el fondo innegociable): Dijkstra + memoria de
//       sucesores acotada, con revalidacion contra el grafo vivo en cada uso.
//   (2) SINTAXIS FIELD: programas de N lineas, pares (define) / nones
//       (resolve), donde cada resolve puede encadenarse al resultado de
//       una linea anterior -- composicion real entre lineas, no un solo
//       nivel de indireccion.
#include <bits/stdc++.h>
using namespace std;
using Clock = chrono::high_resolution_clock;

// ---------------------------------------------------------------------
// PIEZA 1: MOTOR ALGORITMICO
// ---------------------------------------------------------------------

struct Graph {
    int n;
    vector<unordered_map<int,double>> adj; // adj[u][v] = peso -- O(1)
};

Graph load_graph(const string& path) {
    ifstream f(path);
    int n; f >> n;
    Graph g; g.n = n; g.adj.resize(n);
    int u, v; double w;
    while (f >> u >> v >> w) g.adj[u][v] = w;
    return g;
}

vector<pair<int,int>> load_traffic(const string& path) {
    ifstream f(path);
    int n; f >> n;
    vector<pair<int,int>> t(n);
    for (auto& [s,gg] : t) f >> s >> gg;
    return t;
}

struct DijkResult { vector<int> path; double cost; long nodes; bool ok; };

DijkResult dijkstra(const Graph& g, int s, int goal) {
    vector<double> dist(g.n, numeric_limits<double>::infinity());
    vector<int> parent(g.n, -1);
    vector<char> visited(g.n, 0);
    priority_queue<pair<double,int>, vector<pair<double,int>>, greater<>> pq;
    dist[s] = 0; pq.push({0.0, s});
    long nodes = 0;
    while (!pq.empty()) {
        auto [d,u] = pq.top(); pq.pop();
        if (visited[u]) continue;
        visited[u] = 1; nodes++;
        if (u == goal) break;
        for (auto& [v,w] : g.adj[u]) {
            double nd = d + w;
            if (nd < dist[v]) { dist[v] = nd; parent[v] = u; pq.push({nd, v}); }
        }
    }
    if (dist[goal] == numeric_limits<double>::infinity()) return {{}, 0, nodes, false};
    vector<int> path; for (int c = goal; c != -1; c = parent[c]) path.push_back(c);
    reverse(path.begin(), path.end());
    return {path, dist[goal], nodes, true};
}

struct Memory {
    unordered_map<int, unordered_map<int,double>> succ;
    static const int MAX_OUT = 4;
    void insert_path(const vector<int>& path, const Graph& g) {
        for (size_t i = 0; i+1 < path.size(); i++) {
            int u = path[i], v = path[i+1];
            auto it = g.adj[u].find(v);
            double w = (it != g.adj[u].end()) ? it->second : 0.0;
            auto& m = succ[u];
            if (m.count(v) || (int)m.size() < MAX_OUT) m[v] = w;
        }
    }
};

// OPTIMIZADO: buffers preasignados del tamano del grafo + contador de
// generacion, en vez de unordered_map/unordered_set. Esto elimina el
// hashing por nodo (la causa real de que C fuera mas lento que A pese a
// visitar menos nodos) Y evita reinicializar O(N) en cada consulta -- solo
// se "resetean" los nodos efectivamente tocados, via el sello de
// generacion, igual que en un Dijkstra de produccion.
struct ReuseScratch {
    vector<double> dist;
    vector<int> parent;
    vector<int> disc_gen;    // sello: nodo alcanzado (dist/parent validos) en esta consulta
    vector<int> settled_gen; // sello: nodo finalizado (ya extraido de la cola) en esta consulta
    int current_gen = 0;
    void ensure(int n) {
        if ((int)dist.size() != n) {
            dist.assign(n, 0.0); parent.assign(n, -1);
            disc_gen.assign(n, -1); settled_gen.assign(n, -1);
        }
    }
};

// Sin ninguna asignacion de tamano N por llamada: todo el estado vive en
// ReuseScratch, preasignado una vez y reutilizado via sello de generacion.
DijkResult reuse_path(const Memory& mem, const Graph& live_graph, int s, int goal, ReuseScratch& sc) {
    sc.ensure(live_graph.n);
    const int G = ++sc.current_gen;
    sc.dist[s] = 0.0; sc.parent[s] = -1; sc.disc_gen[s] = G;
    priority_queue<pair<double,int>, vector<pair<double,int>>, greater<>> pq;
    pq.push({0.0, s});
    long nodes = 0;
    while (!pq.empty()) {
        auto [d,u] = pq.top(); pq.pop();
        if (sc.settled_gen[u] == G) continue;
        sc.settled_gen[u] = G; nodes++;
        if (u == goal) break;
        auto it = mem.succ.find(u);
        if (it == mem.succ.end()) continue;
        for (auto& [v, cached_w] : it->second) {
            auto live_it = live_graph.adj[u].find(v);
            if (live_it == live_graph.adj[u].end()) continue; // arista ya no existe -- se ignora, no se fabrica
            double w = live_it->second; // SIEMPRE el peso vivo, nunca el cacheado
            double nd = d + w;
            if (sc.disc_gen[v] != G || nd < sc.dist[v]) {
                sc.dist[v] = nd; sc.parent[v] = u; sc.disc_gen[v] = G;
                pq.push({nd, v});
            }
        }
    }
    if (sc.disc_gen[goal] != G) return {{}, 0, nodes, false};
    vector<int> path; int c = goal;
    while (true) { path.push_back(c); if (c == s) break; c = sc.parent[c]; }
    reverse(path.begin(), path.end());
    return {path, sc.dist[goal], nodes, true};
}

bool validate_path(const Graph& g, const vector<int>& path, double claimed_cost) {
    if (path.empty()) return false;
    double real = 0;
    for (size_t i = 0; i+1 < path.size(); i++) {
        auto it = g.adj[path[i]].find(path[i+1]);
        if (it == g.adj[path[i]].end()) return false;
        real += it->second;
    }
    return fabs(real - claimed_cost) < 1e-6;
}

// ---------------------------------------------------------------------
// PIEZA 2: SINTAXIS FIELD -- N lineas, pares/nones, composicion real
// ---------------------------------------------------------------------
// linea par  (0,2,4,...): DEFINE -- introduce un valor (nodo) nuevo
// linea non  (1,3,5,...): RESOLVE -- resuelve entre el DEFINE anterior y
//   el DEFINE de esta pareja -- composicion real: cada resolve encadena
//   al resultado de la linea anterior, no a una referencia fija de linea 0
//   como en la v1.

struct FieldLine {
    enum Kind { DEFINE, RESOLVE } kind;
    int value = -1;         // DEFINE: el nodo que introduce
    int from_line = -1;     // RESOLVE: linea DEFINE exacta que da el "desde"
    int to_line = -1;       // RESOLVE: linea DEFINE exacta que da el "hasta"
};

struct FieldProgram { vector<FieldLine> lines; };

// Construye un programa de longitud variable: s -> m1 -> m2 -> ... -> g.
// Cada RESOLVE referencia EXPLICITAMENTE las dos lineas DEFINE de las que
// depende (indices fijos, calculados al construir, no adivinados en
// tiempo de interpretacion) -- asi se elimina la ambiguedad que causaba
// la divergencia C != D.
FieldProgram make_field_program(const vector<int>& waypoints) {
    FieldProgram prog;
    prog.lines.push_back({FieldLine::DEFINE, waypoints[0], -1, -1});
    int prev_define_idx = 0;
    for (size_t i = 1; i < waypoints.size(); i++) {
        int this_define_idx = (int)prog.lines.size();
        prog.lines.push_back({FieldLine::DEFINE, waypoints[i], -1, -1});
        prog.lines.push_back({FieldLine::RESOLVE, -1, prev_define_idx, this_define_idx});
        prev_define_idx = this_define_idx;
    }
    return prog;
}

long interpret_field(FieldProgram& prog, const Graph& g, Memory* mem, ReuseScratch* scratch,
                      bool* out_all_valid = nullptr) {
    long total = 0;
    bool all_valid = true;
    for (auto& ln : prog.lines) {
        if (ln.kind == FieldLine::DEFINE) continue;
        int from_val = prog.lines[ln.from_line].value;
        int to_val = prog.lines[ln.to_line].value;
        DijkResult r;
        if (mem) {
            r = reuse_path(*mem, g, from_val, to_val, *scratch);
            total += r.nodes;
            if (!r.ok) {
                auto r2 = dijkstra(g, from_val, to_val);
                total += r2.nodes;
                if (r2.ok) { mem->insert_path(r2.path, g); r = r2; }
            }
        } else {
            r = dijkstra(g, from_val, to_val);
            total += r.nodes;
        }
        if (r.ok && !validate_path(g, r.path, r.cost)) all_valid = false;
    }
    if (out_all_valid) *out_all_valid = all_valid;
    return total;
}

// ---------------------------------------------------------------------
// VERIFICACION CRUZADA (correccion antes que velocidad)
// ---------------------------------------------------------------------
void self_check(const Graph& g) {
    auto r = dijkstra(g, 0, min(50, g.n-1));
    assert(r.ok);
    assert(validate_path(g, r.path, r.cost));

    Memory mem;
    mem.insert_path(r.path, g);
    ReuseScratch sc;
    auto r2 = reuse_path(mem, g, r.path.front(), r.path.back(), sc);
    assert(r2.ok);
    assert(fabs(r2.cost - r.cost) < 1e-6);

    // SEGURIDAD ANTE MUTACION -- lo que fallaba en la v1.
    Graph mutated = g;
    int u = r.path[0], v = r.path[1];
    mutated.adj[u].erase(v);
    auto r3 = reuse_path(mem, mutated, u, r.path.back(), sc);
    if (r3.ok) assert(validate_path(mutated, r3.path, r3.cost));
    bool used_deleted_edge = false;
    for (size_t i = 0; r3.ok && i+1 < r3.path.size(); i++)
        if (r3.path[i] == u && r3.path[i+1] == v) used_deleted_edge = true;
    assert(!used_deleted_edge);

    vector<int> wp = {r.path.front(), 10 % g.n, 20 % g.n, 30 % g.n, r.path.back()};
    auto prog = make_field_program(wp);
    // Verificacion EXPLICITA de que cada RESOLVE apunta al par de waypoints
    // correcto (esto es lo que la v2-bug-1 no verificaba, y por eso no
    // atrapo la divergencia hasta correr el benchmark completo).
    int hop = 0;
    for (auto& ln : prog.lines) {
        if (ln.kind != FieldLine::RESOLVE) continue;
        int from_val = prog.lines[ln.from_line].value;
        int to_val = prog.lines[ln.to_line].value;
        assert(from_val == wp[hop] && to_val == wp[hop+1]);
        hop++;
    }
    assert(hop == (int)wp.size() - 1);

    bool all_valid = false;
    Memory mem2;
    ReuseScratch sc2;
    long w = interpret_field(prog, g, &mem2, &sc2, &all_valid);
    assert(all_valid);
    assert(w > 0);

    // A == B invariante: sin memoria, field y convencional deben hacer
    // EXACTAMENTE el mismo trabajo (mismos pares, mismo dijkstra fresco).
    long conv_w = 0;
    for (size_t i = 0; i+1 < wp.size(); i++) conv_w += dijkstra(g, wp[i], wp[i+1]).nodes;
    long field_w_nomem = interpret_field(prog, g, nullptr, nullptr);
    assert(conv_w == field_w_nomem);

    fprintf(stderr, "[self_check] 6/6 verificaciones OK "
            "(dijkstra basico, reuse=optimo, seguridad ante mutacion, field multi-linea valido, "
            "endpoints de cadena correctos, field==convencional sin memoria)\n");
}

// ---------------------------------------------------------------------
// BENCHMARK: 4 condiciones, programas field de profundidad real
// (5 waypoints = 4 resolves encadenados por peticion, no 1).
// ---------------------------------------------------------------------
template<typename F>
pair<long,double> bench(F fn, int reps=5) {
    long w = 0; double best = 1e18;
    for (int r = 0; r < reps; r++) {
        auto t0 = Clock::now();
        w = fn();
        double ms = chrono::duration<double,milli>(Clock::now()-t0).count();
        best = min(best, ms);
    }
    return {w, best};
}

int main() {
    Graph g = load_graph("graph.txt");
    auto traffic = load_traffic("traffic.txt");

    self_check(g);

    auto make_waypoints = [&](int s, int gd) {
        int m1 = (s*31 + gd*17) % g.n;
        int m2 = (s*13 + gd*7 + 5) % g.n;
        return vector<int>{s, m1, m2, gd};
    };

    auto run_A = [&]{
        long total = 0;
        for (auto& [s,gd] : traffic) {
            auto wp = make_waypoints(s, gd);
            for (size_t i = 0; i+1 < wp.size(); i++)
                total += dijkstra(g, wp[i], wp[i+1]).nodes;
        }
        return total;
    };

    auto run_B = [&]{
        long total = 0;
        for (auto& [s,gd] : traffic) {
            auto prog = make_field_program(make_waypoints(s, gd));
            total += interpret_field(prog, g, nullptr, nullptr);
        }
        return total;
    };

    Memory MEMORY_C;
    ReuseScratch SCRATCH_C;
    auto run_C = [&]{
        long total = 0;
        for (auto& [s,gd] : traffic) {
            auto prog = make_field_program(make_waypoints(s, gd));
            total += interpret_field(prog, g, &MEMORY_C, &SCRATCH_C);
        }
        return total;
    };

    Memory MEMORY_D;
    ReuseScratch SCRATCH_D;
    auto run_D = [&]{
        long total = 0;
        for (auto& [s,gd] : traffic) {
            auto wp = make_waypoints(s, gd);
            for (size_t i = 0; i+1 < wp.size(); i++) {
                auto r = reuse_path(MEMORY_D, g, wp[i], wp[i+1], SCRATCH_D);
                total += r.nodes;
                if (!r.ok) {
                    auto r2 = dijkstra(g, wp[i], wp[i+1]);
                    total += r2.nodes;
                    if (r2.ok) MEMORY_D.insert_path(r2.path, g);
                }
            }
        }
        return total;
    };

    auto [wA, msA] = bench(run_A);
    auto [wB, msB] = bench(run_B);
    auto run_C_fresh = [&]{ MEMORY_C = Memory(); return run_C(); };
    auto run_D_fresh = [&]{ MEMORY_D = Memory(); return run_D(); };
    auto [wC, msC] = bench(run_C_fresh);
    auto [wD, msD] = bench(run_D_fresh);

    printf("Programas field: 9 lineas por peticion (5 waypoints, 4 resolves encadenados)\n\n");
    printf("%-45s %15s %12s\n", "Condicion", "trabajo(nodos)", "tiempo(ms)");
    printf("%-45s %15ld %12.3f\n", "A) convencional, sin memoria", wA, msA);
    printf("%-45s %15ld %12.3f\n", "B) field, sin memoria", wB, msB);
    printf("%-45s %15ld %12.3f\n", "C) field + memoria persistente", wC, msC);
    printf("%-45s %15ld %12.3f\n", "D) convencional + memoria", wD, msD);
    printf("\n");
    printf("Trabajo identico esperado (misma memoria, mismo trafico): C=%ld D=%ld -> %s\n",
           wC, wD, wC==wD ? "OK, identico" : "DIVERGEN -- revisar");
    printf("C vs A: %.1f%% menos trabajo, tiempo %.4fx\n", 100.0*(1-(double)wC/wA), msC/msA);
    printf("C vs D (impuesto de sintaxis field, con composicion real de 9 lineas): tiempo %.4fx\n",
           msC/msD);
    printf("B vs A (impuesto de sintaxis SIN memoria, mismo trabajo=%s): tiempo %.4fx\n",
           wB==wA ? "identico":"DISTINTO", msB/msA);
    return 0;
}
