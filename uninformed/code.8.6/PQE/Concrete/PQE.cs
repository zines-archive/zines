//
// Provides a concrete PQE implementation for performing analysis against
// generalized data flow elements.  This file is released as a public
// example of an implementation.  This file is licensed for non-commercial
// research purposes.  It has been taken directly from the Cthulhu framework.
//
// skape
// mmiller@hick.org
// 8/2007
//
using System;
using System.Collections;
using System.Collections.Generic;

using UR.Common;
using UR.Graphs;

using Cthulhu;
using Cthulhu.Types;
using Cthulhu.Graphing;

using Cthulhu.Shared.Graphing;

namespace Cthulhu.Shared.PathDiscovery.Algorithms
{
	/// <summary>
	/// The concrete implementation of Progressive Qualified Elaboration
	/// </summary>
	public class PQE
	{
		/// <summary>
		/// Initializes the PQE instance
		/// </summary>
		/// <param name="state">The engine state</param>
		public PQE(State state)
		{
			this.state = state;
		}

		/// <summary>
		/// Searches for paths between a source and a sink within a set of targets rendering those paths
		/// at a final granularity
		/// </summary>
		/// <param name="targets">The set of targets to find paths within</param>
		/// <param name="source">The source descriptor</param>
		/// <param name="sink">The sink descriptor</param>
		/// <param name="granularity">The granularity to render the paths at, such as Instruction</param>
		/// <returns>The set of flow paths between the source and sink</returns>
		public FlowPathSet Search(
			NormalizableSet targets,
			FlowDescriptor source,
			FlowDescriptor sink,
			NormalizableType granularity)
		{
			DataFlowGraph graph;
			FlowPathSet paths = null;
			
			// Build a data flow graph by first translating the set of targets to the component tier.
			// We start at a general tier to reduce the amount of state that must be rendered at once.
			graph = BuildGraph(targets.Translate(NormalizableType.Component));
			
			// Until we reach a point where the graph is empty, keep iterating
			while (!graph.IsEmpty)
			{
				// Find the set of vertices associated with each flow descriptor
				NormalizableSet sourceVertices = source.SearchGraph(graph);
				NormalizableSet sinkVertices = sink.SearchGraph(graph);

				// Find paths between the source vertices and the sink vertices that were derived
				// from their corresponding flow descriptors
				paths = FindPaths(graph, sourceVertices, sinkVertices);

				// If we've reached our target granularity, then break out of the loop.  We've found
				// the set of paths we set out to locate.
				if (sourceVertices.Granularity == granularity)
					break;

				// Otherwise, we need to elaborate the paths that we found to the next most-specific
				// generalization tier
				graph = BuildGraphFromPaths(paths);
			}

			return paths;
		}

		/// <summary>
		/// Finds flow paths between a set of source and sink vertices within a given data flow graph
		/// </summary>
		/// <param name="graph">The graph to find flow paths within</param>
		/// <param name="sourceVertices">The set of source vertices</param>
		/// <param name="sinkVertices">The set of sink vertices</param>
		/// <returns>The set of unique paths between source and sink</returns>
		private FlowPathSet FindPaths(
			DataFlowGraph graph,
			NormalizableSet sourceVertices,
			NormalizableSet sinkVertices)
		{
			FlowPathSet pathSet = new FlowPathSet(graph.Granularity);

			// Walk through each source vertex
			foreach (Normalizable source in sourceVertices)
			{
				// And through each sink vertex
				foreach (Normalizable sink in sinkVertices)
				{
					ContextSensitiveDataFlowGraphNavigator navigator;
					
					navigator = new ContextSensitiveDataFlowGraphNavigator(graph);
					
					// Find the paths between the current source and sink vertex
					// and add them to the path set
					navigator.Navigate(
						source, 
						new ConstructFlowPathsVisitor(sink, 0, pathSet));
				}
			}

			return pathSet;
		}

		/// <summary>
		/// Construct a data flow graph using the set of supplied targets
		/// </summary>
		/// <param name="targets">The set of target normalizables to build the graph from</param>
		/// <returns>The constructed data flow graph</returns>
		private DataFlowGraph BuildGraph(NormalizableSet targets)
		{
			return DataFlowGraph.Create(state, targets);
		}

		/// <summary>
		/// Construct a data flow graph constrained to a set of specific flow paths
		/// </summary>
		/// <remarks>
		/// The set of flow paths provided is elaborated to the next more specific generalization tier.
		/// </remarks>
		/// <param name="paths">The flow paths to use as a base for constructing the graph</param>
		/// <returns>The data flow graph containing normalizables from a more specific tier</returns>
		private DataFlowGraph BuildGraphFromPaths(FlowPathSet paths)
		{
			DataFlowGraph graph = new DataFlowGraph(state);
			DefaultSet pathIdSet = new DefaultSet();

			// Populate the cache which associates normalizable identifiers to data flow
			// paths at a given granularity
			foreach (FlowPath path in paths)
			{
				foreach (FlowPath.FlowStep step in path.FlowSteps)
					pathIdSet.Add(step.PathIdentifier);
			}

			// Tell the graph to expand the current granularity's path cache to the next more-specific
			// granularity.  For example, we would elaborate the type-level paths to the set of method-level
			// paths which are generalized by the type-level paths.
			graph.PopulateFromElaboratedPaths(
				paths.Granularity,
				pathIdSet);

			return graph;
		}

		/// <summary>
		/// The engine state needed when creating a graph
		/// </summary>
		private State state;
	}
}
