// Shared by the activity queue and the approval page a chat card links to: one approval, described
// exactly as it would run, with every invisible or direction-changing character made visible.
import {visible} from './hosted-text.js';

// Fixed sentences for the warning codes Fabric attaches to a request. Nothing here comes from the agent.
export const WARNINGS = {
  not_reviewed: 'This is not one of the reviewed actions for this app. Read the exact request before approving.',
  delete: 'This deletes something.',
  duplicate_of_uncertain: 'An earlier change like this one could not be confirmed. Check it in the app before approving another.',
  reaches_people: 'Reaches other people.',
  body_routed: 'Fabric placed this request in a stricter permission because of what its body does.',
  // F10.11 part j: a reviewed action that reads before it shows its final request, and one that edits something Fabric did not make.
  prepares_first: 'Fabric runs these steps first. It shows you the exact final request before sending it.',
  not_made_by_fabric: 'Fabric did not make this record, so it asks first.',
};

/**
 * The approval as the owner reviews it. The heading is Fabric's: the operation and app. The agent's own
 * title comes second and is labelled as the agent's. Without the whole exact action, there is no Approve.
 */
export function describeApproval(approval, {tenant = false} = {}) {
  const exact = approval.exact || {complete: false, blocks: []};
  return {heading: `${visible(approval.operation)} in ${visible(approval.appName)}`, agentSays: approval.taskTitle ? `Agent says: “${visible(approval.taskTitle)}”` : null,
    warnings: (approval.warnings || []).map(code => WARNINGS[code]).filter(Boolean),
    account: approval.account ? visible(approval.account) : null, agent: approval.agent ? visible(approval.agent) : null, expiresAt: approval.expiresAt,
    blocks: exact.blocks.map(block => ({label: block.label, text: visible(block.text)})), complete: exact.complete === true,
    // On a developer's approval link there is no workspace to send the person to: they can only reject it (F03.10).
    incomplete: exact.complete === true ? null : tenant ? 'This request is too long to show here in full, so it cannot be approved from this page. You can reject it.' : 'This action is too long to show here in full, so it cannot be approved from this page. Review it in the Fabric workspace, or cancel it.',
    approve: exact.complete === true ? approval.approve : null, cancel: approval.cancel};
}
