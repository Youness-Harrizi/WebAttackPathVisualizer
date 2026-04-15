import { useCallback, useMemo } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  addEdge,
  type Connection,
  type Edge,
  type Node,
  type NodeProps,
  Handle,
  Position,
} from 'reactflow';
import { useStore, SEVERITY_COLOR } from '../store';
import { NODE_BY_ID, outgoing } from '../data/attackLibrary';
import type { Finding } from '../types';

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
        <div>
          <div className="text-[10px] uppercase tracking-wider" style={{ color }}>
            {libNode?.kind ?? 'node'}
          </div>
          <div className="text-xs font-semibold text-slate-100 leading-tight">
            {f.title}
          </div>
          <div className="text-[10px] text-slate-400 mt-0.5 truncate">{f.location}</div>
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

export function ChainView() {
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

  const rfNodes: Node[] = useMemo(() => {
    // Auto-layout: columns by phase, rows stack within a column.
    const phaseOrder = [
      'recon',
      'initial-access',
      'execution',
      'persistence',
      'privilege-escalation',
      'credential-access',
      'lateral-movement',
      'impact',
    ];
    const byPhase: Record<string, Finding[]> = {};
    for (const f of engagementFindings) {
      const p = NODE_BY_ID[f.nodeId]?.phase ?? 'initial-access';
      (byPhase[p] ??= []).push(f);
    }
    const out: Node[] = [];
    phaseOrder.forEach((phase, colIdx) => {
      const list = byPhase[phase] ?? [];
      list.forEach((f, rowIdx) => {
        out.push({
          id: f.id,
          type: 'finding',
          position: { x: colIdx * 280, y: rowIdx * 110 },
          data: { finding: f },
        });
      });
    });
    return out;
  }, [engagementFindings]);

  const rfEdges: Edge[] = useMemo(
    () =>
      findingEdges
        .filter((e) => e.engagementId === activeEngagementId)
        .map((e) => ({
          id: e.id,
          source: e.from,
          target: e.to,
          label: e.rationale,
          labelStyle: { fill: '#94a3b8', fontSize: 10 },
          labelBgStyle: { fill: '#0b0f17' },
          animated: true,
        })),
    [findingEdges, activeEngagementId],
  );

  const onConnect = useCallback(
    (params: Connection) => {
      if (params.source && params.target) {
        const srcNode = NODE_BY_ID[findings.find((f) => f.id === params.source)?.nodeId ?? ''];
        const tgtNode = NODE_BY_ID[findings.find((f) => f.id === params.target)?.nodeId ?? ''];
        const canonical = srcNode && tgtNode ? outgoing(srcNode.id).find((e) => e.to === tgtNode.id) : undefined;
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
        <div>
          <div className="text-slate-200 font-semibold mb-1">No findings yet</div>
          <p className="text-xs text-slate-400 max-w-sm">
            Switch to the <b>Matrix</b> view and click a technique to add a finding. Findings
            placed on the chain canvas can be connected by dragging from the right handle of
            one node to the left handle of another.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1">
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        nodeTypes={nodeTypes}
        onConnect={onConnect}
        onEdgesDelete={onEdgesDelete}
        onNodesDelete={onNodesDelete}
        fitView
        proOptions={{ hideAttribution: false }}
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
