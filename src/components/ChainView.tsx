import { useCallback, useMemo } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  type Connection,
  type Edge,
  type Node,
  type NodeProps,
  Handle,
  Position,
} from 'reactflow';
import dagre from '@dagrejs/dagre';
import { useStore, SEVERITY_COLOR } from '../store';
import { NODE_BY_ID, outgoing } from '../data/attackLibrary';
import type { Finding } from '../types';

interface Props {
  onEditFinding: (f: Finding) => void;
}

function FindingNode({ data, selected }: NodeProps<{ finding: Finding }>) {
  const f = data.finding;
  const libNode = NODE_BY_ID[f.nodeId];
  const color =
    libNode?.kind === 'vulnerability'
      ? '#ef4444'
      : libNode?.kind === 'technique'
      ? '#f59e0b'
      : '#8b5cf6';
  return (
    <div
      className={`rounded-md border bg-panel px-3 py-2 min-w-[180px] max-w-[240px] ${
        selected ? 'border-accent' : 'border-border'
      }`}
      style={{ boxShadow: selected ? '0 0 0 2px rgba(239,68,68,0.3)' : undefined }}
    >
      <Handle type="target" position={Position.Left} style={{ background: '#475569' }} />
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-[10px] uppercase tracking-wider" style={{ color }}>
            {libNode?.kind ?? 'node'}
          </div>
          <div className="text-xs font-semibold text-slate-100 leading-tight truncate">
            {f.title}
          </div>
          <div className="text-[10px] text-slate-400 mt-0.5 truncate">{f.location || '—'}</div>
        </div>
        <span
          className="shrink-0 text-[10px] rounded px-1.5 py-0.5 font-semibold uppercase"
          style={{ background: SEVERITY_COLOR[f.severity], color: '#0b0f17' }}
        >
          {f.severity[0]}
        </span>
      </div>
      <Handle type="source" position={Position.Right} style={{ background: '#475569' }} />
    </div>
  );
}

const nodeTypes = { finding: FindingNode };

const NODE_W = 220;
const NODE_H = 72;

function layout(nodes: Finding[], edges: { from: string; to: string }[]) {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: 'LR', nodesep: 24, ranksep: 80, marginx: 20, marginy: 20 });
  g.setDefaultEdgeLabel(() => ({}));
  for (const n of nodes) g.setNode(n.id, { width: NODE_W, height: NODE_H });
  for (const e of edges) if (g.hasNode(e.from) && g.hasNode(e.to)) g.setEdge(e.from, e.to);
  dagre.layout(g);
  const positions: Record<string, { x: number; y: number }> = {};
  for (const n of nodes) {
    const p = g.node(n.id);
    if (p) positions[n.id] = { x: p.x - NODE_W / 2, y: p.y - NODE_H / 2 };
  }
  return positions;
}

export function ChainView({ onEditFinding }: Props) {
  const activeEngagementId = useStore((s) => s.activeEngagementId);
  const findings = useStore((s) => s.findings);
  const findingEdges = useStore((s) => s.findingEdges);
  const addEdgeStore = useStore((s) => s.addEdge);
  const deleteEdgeStore = useStore((s) => s.deleteEdge);
  const deleteFinding = useStore((s) => s.deleteFinding);

  const engagementFindings = useMemo(
    () => findings.filter((f) => f.engagementId === activeEngagementId),
    [findings, activeEngagementId],
  );
  const engagementEdges = useMemo(
    () => findingEdges.filter((e) => e.engagementId === activeEngagementId),
    [findingEdges, activeEngagementId],
  );

  const positions = useMemo(
    () => layout(engagementFindings, engagementEdges),
    [engagementFindings, engagementEdges],
  );

  const rfNodes: Node[] = useMemo(
    () =>
      engagementFindings.map((f) => ({
        id: f.id,
        type: 'finding',
        position: positions[f.id] ?? { x: 0, y: 0 },
        data: { finding: f },
      })),
    [engagementFindings, positions],
  );

  const rfEdges: Edge[] = useMemo(
    () =>
      engagementEdges.map((e) => ({
        id: e.id,
        source: e.from,
        target: e.to,
        label: e.rationale,
        labelStyle: { fill: '#94a3b8', fontSize: 10 },
        labelBgStyle: { fill: '#0b0f17' },
        animated: true,
      })),
    [engagementEdges],
  );

  const onConnect = useCallback(
    (params: Connection) => {
      if (params.source && params.target) {
        const srcNode = NODE_BY_ID[findings.find((f) => f.id === params.source)?.nodeId ?? ''];
        const tgtNode = NODE_BY_ID[findings.find((f) => f.id === params.target)?.nodeId ?? ''];
        const canonical =
          srcNode && tgtNode ? outgoing(srcNode.id).find((e) => e.to === tgtNode.id) : undefined;
        addEdgeStore(params.source, params.target, canonical?.rationale);
      }
    },
    [addEdgeStore, findings],
  );

  const onEdgesDelete = useCallback(
    (edges: Edge[]) => {
      edges.forEach((e) => deleteEdgeStore(e.id));
    },
    [deleteEdgeStore],
  );

  const onNodesDelete = useCallback(
    (nodes: Node[]) => {
      nodes.forEach((n) => deleteFinding(n.id));
    },
    [deleteFinding],
  );

  if (engagementFindings.length === 0) {
    return (
      <div className="flex-1 flex items-center justify-center text-center p-8">
        <div className="max-w-md">
          <div className="text-slate-200 font-semibold mb-1">No findings yet</div>
          <p className="text-xs text-slate-400 mb-4">
            Switch to the <b>Matrix</b> view (press <kbd className="kbd">m</kbd>) and click a
            technique to add a finding. Findings on this canvas can be connected by dragging from
            the right handle of one node to the left handle of another. Delete with{' '}
            <kbd className="kbd">⌫</kbd>.
          </p>
          <style>{`
            .kbd {
              background: #1f2937; border: 1px solid #334155;
              border-radius: 4px; padding: 1px 5px;
              font-family: ui-monospace, monospace; font-size: 10px;
            }
          `}</style>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 relative">
      <div className="absolute top-2 left-2 z-10 bg-panel/90 border border-border rounded px-2 py-1 text-[10px] text-slate-400">
        Drag handle to link · click node to edit · <kbd className="kbd">⌫</kbd> to delete
        <style>{`
          .kbd {
            background: #1f2937; border: 1px solid #334155;
            border-radius: 3px; padding: 0 4px;
            font-family: ui-monospace, monospace; font-size: 10px;
          }
        `}</style>
      </div>
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        nodeTypes={nodeTypes}
        onConnect={onConnect}
        onEdgesDelete={onEdgesDelete}
        onNodesDelete={onNodesDelete}
        onNodeClick={(_, node) => {
          const f = findings.find((x) => x.id === node.id);
          if (f) onEditFinding(f);
        }}
        fitView
      >
        <Background color="#1f2937" gap={16} />
        <Controls />
        <MiniMap
          style={{ background: '#121826' }}
          nodeColor={(n) => {
            const f = (n.data as any)?.finding as Finding | undefined;
            return f ? SEVERITY_COLOR[f.severity] : '#475569';
          }}
          maskColor="rgba(11,15,23,0.6)"
        />
      </ReactFlow>
    </div>
  );
}
