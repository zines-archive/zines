//
// Abstract implementation of Progressive Qualified Elaboration (PQE).  
// This file is licensed for non-commercial research purposes.
//
// skape
// mmiller@hick.org
// 8/2007
//
using System;
using System.Collections.Generic;

namespace UR.StaticAnalysis.Algorithms.PQE
{
	#region Abstract Interfaces
	/// <summary>
	/// Describes an element that may be found in a graph at one or more tiers
	/// </summary>
	/// <remarks>
	/// An example of a descriptor would be the assembly, type, method name, and parameter
	/// associated with a source or a sink, such as: 
	/// 
	/// System/System.Data.SqlClient.SqlCommand/set_CommandText/parameter 1
	/// </remarks>
	public interface IFlowDescriptor
	{
	}

	/// <summary>
	/// A generic graph containing vertices of the type E
	/// </summary>
	/// <typeparam name="E">The generic element type, typically object</typeparam>
	public interface IGraph<E, P>
	{
		bool IsEmpty { get; }

		/// <summary>
		/// Gets the set of vertices associated with the supplied flow descriptor
		/// </summary>
		/// <param name="descriptor">The descriptor to find vertices of</param>
		/// <returns>A set of vertices</returns>
		IElementSet<E> GetVerticesFromDescriptor(IFlowDescriptor descriptor);
		/// <summary>
		/// Finds paths between a set of source vertices and a set of sink vertices
		/// </summary>
		/// <param name="sourceVertices">The set of source vertices</param>
		/// <param name="sinkVertices">The set of sink vertices</param>
		/// <returns>A set of paths</returns>
		IPathSet<P> FindPaths(IElementSet<E> sourceVertices, IElementSet<E> sinkVertices);
	}

	/// <summary>
	/// Constructs a graph given a set of elements
	/// </summary>
	/// <typeparam name="E">The element type</typeparam>
	/// <typeparam name="P">The path type</typeparam>
	public interface IGraphBuilder<E, P>
	{
		/// <summary>
		/// Constructs an abstract graph using the set of graph elements provided
		/// </summary>
		/// <param name="elements">The set of graph elements to build the graph with</param>
		/// <returns>A graph populated with information relevant to the supplied elements</returns>
		IGraph<E, P> BuildGraph(IElementSet<E> elements);
		/// <summary>
		/// Constructs an abstract graph using the path set provided
		/// </summary>
		/// <param name="elements">The set of paths found within a previous graph</param>
		/// <returns>A graph populated with information relevant to the next most specific tier of the paths provided</returns>
		IGraph<E, P> BuildGraph(IPathSet<P> paths);
	}

	/// <summary>
	/// A set of opaque instances
	/// </summary>
	/// <typeparam name="T">The type of the instances contained within the set</typeparam>
	public interface ISet<T> 
	{
		/// <summary>
		/// True if there are no members in the set
		/// </summary>
		bool IsEmpty { get; }
	}

	/// <summary>
	/// A set of paths
	/// </summary>
	/// <typeparam name="P">The path type</typeparam>
	public interface IPathSet<P> : ISet<P>
	{
		/// <summary>
		/// Elaborates the path set to a more specific set of paths
		/// </summary>
		/// <remarks>
		/// Elaboration is the process of taking information from a more general tier, such 
		/// as the type tier, and expanding it to information from a more specific tier,
		/// such as the method tier.  The expansion is constrained by the set of paths
		/// found in the less specific tier.
		/// </remarks>
		/// <returns>A set of paths from the next most-specific tier</returns>
		IPathSet<P> Elaborate();
	}

	/// <summary>
	/// Contains zero or more elements
	/// </summary>
	/// <typeparam name="E">The element type</typeparam>
	public interface IElementSet<E> : ISet<E>
	{
	}
	#endregion

	/// <summary>
	/// Provides a generic flow set reduction implementation
	/// </summary>
	/// <typeparam name="P">The specific path type</typeparam>
	/// <typeparam name="E">The specific element type</typeparam>
	public class PQE<P, E>
	{
		/// <summary>
		/// Initializes the flow set reduction instance
		/// </summary>
		/// <param name="graphBuilder">The factory to use when building graphs</param>
		public PQE(IGraphBuilder<E, P> graphBuilder)
		{
			this.graphBuilder = graphBuilder;
		}

		/// <summary>
		/// Gets detailed paths between a set of sources and a set of sinks using PQE
		/// </summary>
		/// <param name="elements">The initial set of elements to use</param>
		/// <param name="sourceDescriptor">Describes an analysis source</param>
		/// <param name="sinkDescriptor">Describes an analysis sink</param>
		/// <returns>The set of paths found at the most specific generalization tier</returns>
		public IPathSet<P> GetFlowPaths(
			IElementSet<E> elements,
			IFlowDescriptor sourceDescriptor,
			IFlowDescriptor sinkDescriptor)
		{
			IGraph<E, P> graph = graphBuilder.BuildGraph(elements);
			IPathSet<P> paths = null;

			// Loop until we get the most specific tier
			while (!graph.IsEmpty)
			{
				// Find the sets of vertices that are associated with the source and sink descriptor
				IElementSet<E> sourceVertices = graph.GetVerticesFromDescriptor(sourceDescriptor);
				IElementSet<E> sinkVertices = graph.GetVerticesFromDescriptor(sinkDescriptor);

				// Find paths between the source vertices and the sink vertices
				paths = graph.FindPaths(sourceVertices, sinkVertices);
			
				// Elaborate the path set that is found to the next generalization tier
				// and use the set of elaborated paths to construct the next flow graph
				graph = graphBuilder.BuildGraph(paths.Elaborate());
			}

			return paths;
		}

		/// <summary>
		/// The instance used to construct abstract graphs
		/// </summary>
		private IGraphBuilder<E, P> graphBuilder;
	}
}
