import networkx as nx
import matplotlib.pyplot as plt

def create_network_scanner_graph():
    G = nx.DiGraph()

    # Root node
    G.add_node("Network Scanner App", color='red')

    # UI Buttons (User Actions)
    actions = [
        "Scan Network", "Search Open Ports", "Enumerate Services", 
        "Vulnerability Scan", "Sniff HTTP Packets", "Sniff HTTPS Packets"
    ]
    
    for action in actions:
        G.add_edge("Network Scanner App", action, color='blue')
    
    # Functions (Back-end Logic)
    functions = {
        "Scan Network": "scan_network()",
        "Search Open Ports": "scan_open_ports(ip_address)",
        "Enumerate Services": "enumerate_services(ip_range)",
        "Vulnerability Scan": "scan_vulnerability(ip_address)",
        "Sniff HTTP Packets": "sniff_http_packets(ip_address)",
        "Sniff HTTPS Packets": "sniff_https_packets(ip_address)"
    }
    
    for action, function in functions.items():
        G.add_edge(action, function, color='green')
    
    # Results (Popups)
    results = {
        "scan_network()": "Scan Results Popup",
        "scan_open_ports(ip_address)": "Open Ports Popup",
        "enumerate_services(ip_range)": "Enumerated Services Popup",
        "scan_vulnerability(ip_address)": "Vulnerability Scan Results Popup",
        "sniff_http_packets(ip_address)": "Sniffed HTTP Packets Popup",
        "sniff_https_packets(ip_address)": "Sniffed HTTPS Packets Popup"
    }
    
    for function, popup in results.items():
        G.add_edge(function, popup, color='orange')
    
    return G

# Create graph
G = create_network_scanner_graph()

# Define colors for edges
edge_colors = [G[u][v]['color'] for u, v in G.edges()]

# Use a circular layout to spread nodes evenly
pos = nx.kamada_kawai_layout(G)

# Draw the graph
plt.figure(figsize=(12, 7))
nx.draw(G, pos, with_labels=True, node_color='lightblue', edge_color=edge_colors, 
        node_size=3000, font_size=9, font_weight='bold', arrows=True)

plt.title("Network Scanner App - Graph Representation")
plt.show()
