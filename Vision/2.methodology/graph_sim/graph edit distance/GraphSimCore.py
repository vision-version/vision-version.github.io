import os
import sys
import re
from ctypes import *
import numpy
import math
sys.path.append("2.methodology/graph_sim/hungarian")
#from matplotlib import pyplot as plt
import networkx as nx
import os
import hungarian
import json
import requests
from tqdm import tqdm

USE_WEIGHT = True

DEBUG = False
#DEBUG = True


######################################################
# *************graph_edit_distance********************
######################################################
def graph_node_distance(g1, g2):
	MAX_VALUE=10000
	cost_matrix = []
	g1_indexs = list(g1.nodes())
	g2_indexs = list(g2.nodes())
	#print g1_indexs, g2_indexs, len(g1_indexs), len(g2_indexs)
  
	matrix_len = max(len(g1), len(g2))
	min_len = min(len(g1), len(g2))
	if min_len == 0:
		return MAX_VALUE
	
	# diff = min_len *1.0 / matrix_len
	# # print diff
	# if diff < 0.5:
	# 	return MAX_VALUE
	for row_id in range(matrix_len):
		row = []
		for column_id in range(matrix_len):
			src = obtain_node_feature(g1, g1_indexs, row_id)
			# print(g2_indexs)
			dst = obtain_node_feature(g2, g2_indexs, column_id)
			cost = cal_nodecost(src, dst)
			#print row_id, column_id,  src, dst, cost
			if USE_WEIGHT:
				src_weight = obtain_node_weight(g1, g1_indexs, row_id)
				dst_weight = obtain_node_weight(g2, g2_indexs, column_id)
				cost_weight =(cost)*(src_weight+dst_weight)/2
				#cost_weight =1-(1-cost)*src_weight*dst_weight
				# cost_weight =(cost)*(1 / src_weight * 1 / dst_weight)/2
				cost = cost_weight

			row.append(cost)
		cost_matrix.append(row)
	if len(cost_matrix) == 0:
		return MAX_VALUE
	mapping = hungarian.lap(cost_matrix)
	#print '-------------- cost matrix -------------'
	#print cost_matrix

	#print '-------------- matrix mapping-------------'
	#print mapping
	distance = caldistance(mapping, cost_matrix)
	return distance

def graph_edge_distance(g1, g2):
	cost_matrix = []
	#print g1.edges(), g2.edges()
	g1_indexs = list(g1.edges())
	g2_indexs = list(g2.edges())
	matrix_len = max(len(g1), len(g2))
	min_len = min(len(g1), len(g2))
	if min_len == 0: 
		return 0

	for row_id in range(matrix_len):
		row = []
		for column_id in range(matrix_len):
			src = obtain_edge_feature(g1, g1_indexs, row_id)
			dst = obtain_edge_feature(g2, g2_indexs, column_id)

			if src is None or dst is None: cost = 0
			else: cost = cal_edgecost(src, dst)
			# print(f"cost is {cost}")
			# use weight
			if USE_WEIGHT:
				src_weight = obtain_edge_weight(g1, g1_indexs, row_id)
				dst_weight = obtain_edge_weight(g2, g2_indexs, column_id)
				cost_weight = (cost)*(src_weight+dst_weight)/2
				cost = cost_weight
			row.append(cost)
		cost_matrix.append(row)
	if len(cost_matrix) == 0:
		return -1
	mapping = hungarian.lap(cost_matrix)
	# print cost_matrix,mapping
	distance = caldistance(mapping, cost_matrix)
	return distance

def cal_edgecost(edge1, edge2):
	src_cost = cal_nodecost(edge1[0], edge2[0])
	dst_cost = cal_nodecost(edge1[1], edge2[1])
	return (src_cost + dst_cost)/2

def cal_nodecost(node1_vec, node2_vec):

	if(node1_vec=="dummy_node" or node2_vec=="dummy_node"):
		return 1

	if node1_vec == node2_vec:
		return 0

	sim = node_dl_sim(node1_vec, node2_vec)
	val = 1 - sim 
	return val


def obtain_edge_weight(g, g_indexes, edge_id):
	g_len = len(g_indexes)
	if edge_id <= (g_len - 1):
		edge = g_indexes[edge_id]
		#print 'obtain edge', edge
		if 'weight' in g.node[edge[0]]:
			src = g.node[edge[0]]['weight']
		else:
			src = 0
		if 'weight' in g.node[edge[1]]:
			dst = g.node[edge[1]]['weight']
		else:
			dst = 0
		return max(src, dst)
	else:
		return 0


def obtain_edge_feature(g, g_indexes, edge_id):
	g_len = len(g_indexes)
	if edge_id <= (g_len - 1):
		edge = g_indexes[edge_id]
		#print 'obtain edge', edge
		if 'node_string' in g.node[edge[0]]:
			src = g.node[edge[0]]['node_string']
		else:
			src = 'dummy_node'
		if 'node_string' in g.node[edge[1]]:
			dst = g.node[edge[1]]['node_string']
		else:
			dst = 'dummy_node'
		return (src, dst)
	else:
		return None #("dummy_node","dummy_node")


def obtain_node_weight(g, g_indexes, node_id):
	if not USE_WEIGHT:
		return 1.0
	g_len = len(g_indexes)
	if node_id <=(g_len - 1):
		node=g_indexes[node_id]

		return g.node[node]['weight']
	else:
		return 1.0


def obtain_node_feature(g, g_indexes, node_id):
	g_len = len(g_indexes)
	if node_id <=(g_len - 1):
		node=g_indexes[node_id]
		# print(g.node[node])
		# print(node_id)
		return g.node[node]['node_string']
	else:
		return "dummy_node"


def obtain_zero_cnt(g):
	# Get zero node count
	g_indexes = list(g.nodes()) 
	zero_node_cnt = 0
	for index in g_indexes:
		node_v = g.node[index]['blines']
		if len(node_v) == 0: zero_node_cnt+=1
	return zero_node_cnt


def caldistance(mapping, cost_matrix):
	cost = 0 
	for i in range(len(mapping[0])):
		cost += cost_matrix[i][mapping[0][i]]
	return cost

def node_cos_sim(vector1,vector2):
# Use cos value to compute the similarity of two nodes
	dot_product = 0.0
	normA = 0.0
	normB = 0.0
	for a,b in zip(vector1,vector2):
		dot_product += a*b
		normA += a**2
		normB += b**2
	if normA == 0.0 or normB == 0.0:
		return 0   
	else:
		return dot_product / ((normA*normB)**0.5)

def node_ecul_sim(v1, v2):
# Use eculidean value to compute the similarity of two nodes
	v1 = numpy.array(v1)
	v2 = numpy.array(v2)
	v1_norm = numpy.linalg.norm(v1) 
	v2_norm = numpy.linalg.norm(v2) 
	#if v1_norm == 0 and v2_norm == 0: # v1 == v2 also return 1
	#	return 1  
	if v1_norm == 0 or v2_norm == 0:
		return 0
	dis = numpy.linalg.norm(v1 - v2)
	return 1.0 - float(dis)/(v1_norm*v2_norm)

def node_dl_sim(v1, v2):
	if v1 == "" or v2 == "":
		return 0
	global cachedUnixCoderSim 
	if v1 not in cachedUnixCoderSim:
		cachedUnixCoderSim[v1] = {}
	if v2 not in cachedUnixCoderSim[v1]:
		url = "http://127.0.0.1:10000/calculate_similarity?string1={}&string2={}".format(v1, v2)
		if "#" in url: url = url.replace("#", "")

		response = requests.get(url)

		if response.status_code == 200:

			# print(url)
			result = response.json()
			cachedUnixCoderSim[v1][v2] = result["similarity_score"]
			# print(result)
			return result["similarity_score"]
		else:
			print("Request failed with status code:", response.status_code)
			# print("Response content:", response.text)
	else:
		# print(f"cached sim score is {cachedUnixCoderSim[v1][v2]}")
		return cachedUnixCoderSim[v1][v2]
######################################################
# *************main function************************** 
######################################################
# Calculate the weighted similarity by the node distance, edge distance and node count of two graphs
def weighted_similarity(g_node1, g_node2, node_dis, edge_dis):
	feature_dis = (node_dis + math.sqrt(edge_dis)) / (g_node1 + g_node2) # difference by feature
	size_dis = abs(float(g_node1 - g_node2)) / (g_node1 + g_node2) # difference by size
	# zero_dis = abs(float(zero_cnt1 - zero_cnt2))/(g_node1 + g_node2)	 

	alpha = 1.15
	beta = 0.05
	gamma = 0.05 
	dis = feature_dis*alpha + size_dis*beta
	sim = 1 - dis
	return sim if sim > 0 else 0


# Compute similarity of two WFGs
def compare_wfg(subcfg1, subcfg2):
	cfg_node_cnt1 = len(subcfg1.nodes())
	cfg_node_cnt2 = len(subcfg2.nodes())
	if cfg_node_cnt1 == 0 or cfg_node_cnt2 == 0:
		#print "CFG node cnt is %s, %s" % (cfg_node_cnt1, cfg_node_cnt2)
		return 0
	min_cnt = min([cfg_node_cnt1, cfg_node_cnt2])
	max_cnt = max([cfg_node_cnt1, cfg_node_cnt2])

	if max_cnt > 3*min_cnt:
		#print cfg_node_cnt1, cfg_node_cnt2, 0
		return 0

	node_dis = graph_node_distance(subcfg1,subcfg2)

	edge_dis = graph_edge_distance(subcfg1,subcfg2)
	# print("Node-distance:", node_dis)
	# print("Edge-distance:", edge_dis)
	# zero_cnt1 = obtain_zero_cnt(subcfg1)
	# zero_cnt2 = obtain_zero_cnt(subcfg2)
	#print("Edge-distance:", edge_dis)
	sim = weighted_similarity(cfg_node_cnt1, cfg_node_cnt2, node_dis, edge_dis )

	os.system("rm *.plist")
	#print cfg_node_cnt1, cfg_node_cnt2, node_dis, edge_dis, sim
	return round(sim,3)

# fig = plt.figure()
# ax1 = fig.add_subplot(2,1,1)
# nx.draw_networkx(subcfg1)
# ax2 = fig.add_subplot(2,1,2)
# nx.draw_networkx(subcfg2)
# plt.show()

def load_wfg(wfg_file):
	with open(wfg_file, "r") as fr:
		wfg_dict = json.load(fr)
	wfg = dict2graph(wfg_dict)
	return wfg

def dict2graph(wfg_dict):
	graph = nx.DiGraph() 
	graph_dict = wfg_dict
	nodes = graph_dict['nodes']
	for index, edge in enumerate(graph_dict['edges']):
		graph_dict['edges'][index] = tuple(edge)
		# print(edge)
		# print(graph_dict['edges'][index])

	edges = graph_dict['edges']
	node_dict = graph_dict['node_dicts']
	
	graph.add_nodes_from(nodes) 
	graph.add_edges_from(edges) 
	for node_id in nodes: 
		graph.node[node_id].update(node_dict[node_id])
	return graph

def simScore(githubGraph, jarGraph, cachedunixCoderSim):
	global cachedUnixCoderSim
	cachedUnixCoderSim = cachedunixCoderSim
	wfg1 = load_wfg(githubGraph)
	wfg2 = load_wfg(jarGraph)

	if wfg1 == None or wfg2 == None:
		# print('WFG is None')
		raise ValueError
	sim = compare_wfg(wfg1, wfg2)
	# print ("Similarity of two WFGs: ", sim)	
	return sim, cachedUnixCoderSim
if __name__=="__main__":
	# "searchnum = no if slicing is not required"
	# arg1: source cfg dump file
	# arg2: source c file, used for slicing, or 'no' to denote no slicing
	# arg3: line_no of vulnerable codes, or 'no' for identifying sensitive lines
	# arg4,5,6: same meanings but for target code

	wfg1 = load_wfg("2.methodology/patch_featuregraph_generate/weighted_graph/CVE-2019-20445_new.json")
	wfg2 = load_wfg("2.methodology/patch_featuregraph_generate/weighted_graph/CVE-2019-20445_old.json")

	# wfg1 = load_wfg("/2.methodology/graph_sim/hungarian/wfg1.json")
	# wfg2 = load_wfg("/2.methodology/graph_sim/hungarian/wfg3.json")

	if wfg1 == None or wfg2 == None:
		print('WFG is None')
		raise ValueError
	sim = compare_wfg(wfg1, wfg2)
	print ("Similarity of two WFGs: ", sim)
