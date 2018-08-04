from csirtg_indicator import Indicator

import networkx as nx
import os
from pprint import pprint

PATH = os.getenv('GEXF_PATH', 'indicators.gexf')


def get_lines(data, path=PATH):
    g = nx.Graph()

    for i in data:
        g.add_node(i['indicator'], itype=i['itype'])
        # for t in i.get('tags', []):
        #     g.add_node(t)
        #     g.add_edge(i['indicator'], t)

        for a in ['cc']:
            if not i.get(a):
                continue

            g.add_node(i[a])
            g.add_edge(i['indicator'], i[a])

    nx.write_gexf(g, path, prettyprint=True)

    # import matplotlib.pyplot as plt
    # nx.draw(g, with_labels=True)
    # plt.draw()
    # plt.show()
    return ['Graph generated successfully: %s' % path]
