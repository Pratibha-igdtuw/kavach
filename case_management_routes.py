"""
Case Management Routes & Socket Events for KAVACH
Add these to app.py after the existing routes.

Integration points:
  1. Call init_case_management_db() in app initialization
  2. Register these routes with the Flask app
  3. Register these socket events with the SocketIO instance
"""
import json
import time
from flask import jsonify, request, session, redirect, url_for
from flask_socketio import join_room, leave_room
from functools import wraps

# Import the case management storage functions
# In the actual app.py, these will be imported from storage.py extensions
# (see integration instructions at the bottom of this file)


def analyst_required(f):
    """Decorator: ensure user is analyst or admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("role") not in ("analyst", "admin"):
            return jsonify({"error": "Unauthorized"}), 403
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# INCIDENT MANAGEMENT ROUTES (REST API)
# ============================================================================

def register_case_management_routes(app, socketio, case_storage, log_audit_and_emit):
    """Register all case management routes with a Flask app.
    
    Expected signature:
      register_case_management_routes(
        app,  # Flask app
        socketio,  # Flask-SocketIO instance
        case_storage,  # module containing case mgmt functions (from case_management_storage.py)
        log_audit_and_emit,  # function(action, sector=None, detail="")
      )
    """
    
    @app.route("/incidents", methods=["GET"])
    @analyst_required
    def list_incidents_view():
        """List all incidents with filters (status, sector)."""
        status = request.args.get("status", "open")
        sector = request.args.get("sector")
        
        incidents = case_storage.list_incidents(status=status, sector=sector)
        stats = case_storage.incident_stats()
        
        return jsonify({
            "incidents": incidents,
            "stats": stats,
        })
    
    
    @app.route("/incidents/create", methods=["POST"])
    @analyst_required
    def create_incident_api():
        """Create a new incident."""
        data = request.get_json() or {}
        title = data.get("title", "").strip()
        description = data.get("description", "").strip()
        sector = data.get("sector")
        severity = data.get("severity", "medium")
        
        if not title:
            return jsonify({"error": "Title is required"}), 400
        if severity not in ("low", "medium", "high", "critical"):
            return jsonify({"error": "Invalid severity"}), 400
        
        creator = session.get("display_name", "Unknown")
        incident_id = case_storage.create_incident(
            title, description, sector, severity, creator
        )
        
        log_audit_and_emit("Created incident", sector=sector, detail=f"#{incident_id}: {title}")
        socketio.emit("incident_created", {"incident_id": incident_id, "title": title})
        
        return jsonify({"incident_id": incident_id}), 201
    
    
    @app.route("/incidents/<int:incident_id>", methods=["GET"])
    @analyst_required
    def get_incident_detail(incident_id):
        """Fetch full incident detail with alerts, links, comments, timeline."""
        incident = case_storage.get_incident(incident_id)
        if not incident:
            return jsonify({"error": "Incident not found"}), 404
        
        alerts = case_storage.get_incident_alerts(incident_id)
        links = case_storage.get_incident_links(incident_id)
        comments = case_storage.get_incident_comments(incident_id)
        timeline = case_storage.get_incident_timeline(incident_id)
        suggestions = case_storage.suggest_incident_links(incident_id)
        
        return jsonify({
            "incident": incident,
            "alerts": alerts,
            "links": links,
            "comments": comments,
            "timeline": timeline,
            "suggestions": suggestions,
        })
    
    
    @app.route("/incidents/<int:incident_id>", methods=["PUT"])
    @analyst_required
    def update_incident_api(incident_id):
        """Update incident metadata."""
        if not case_storage.get_incident(incident_id):
            return jsonify({"error": "Incident not found"}), 404
        
        data = request.get_json() or {}
        updates = {}
        
        for key in ["title", "description", "status", "severity", "root_cause", "resolution_summary"]:
            if key in data:
                updates[key] = data[key]
        
        if not updates:
            return jsonify({"error": "No fields to update"}), 400
        
        case_storage.update_incident(incident_id, **updates)
        
        log_audit_and_emit(
            f"Updated incident #{incident_id}",
            detail=f"Fields: {', '.join(updates.keys())}"
        )
        
        socketio.emit("incident_updated", {
            "incident_id": incident_id,
            "updates": updates,
        })
        
        return jsonify({"success": True})
    
    
    @app.route("/incidents/<int:incident_id>/close", methods=["POST"])
    @analyst_required
    def close_incident_api(incident_id):
        """Close an incident with root cause and resolution."""
        if not case_storage.get_incident(incident_id):
            return jsonify({"error": "Incident not found"}), 404
        
        data = request.get_json() or {}
        root_cause = data.get("root_cause", "")
        resolution = data.get("resolution_summary", "")
        
        closer = session.get("display_name", "Unknown")
        case_storage.close_incident(incident_id, root_cause, resolution, closer)
        
        log_audit_and_emit(f"Closed incident #{incident_id}", detail=f"Root cause: {root_cause[:50]}")
        socketio.emit("incident_closed", {"incident_id": incident_id})
        
        return jsonify({"success": True})
    
    
    @app.route("/incidents/<int:incident_id>/delete", methods=["DELETE"])
    @analyst_required
    def delete_incident_api(incident_id):
        """Delete an incident (cascades)."""
        incident = case_storage.get_incident(incident_id)
        if not incident:
            return jsonify({"error": "Incident not found"}), 404
        
        case_storage.delete_incident(incident_id)
        log_audit_and_emit("Deleted incident", detail=f"#{incident_id}: {incident.get('title')}")
        socketio.emit("incident_deleted", {"incident_id": incident_id})
        
        return jsonify({"success": True})
    
    
    # ========================================================================
    # ALERT ↔ INCIDENT LINKING
    # ========================================================================
    
    @app.route("/incidents/<int:incident_id>/alerts/add", methods=["POST"])
    @analyst_required
    def add_alert_to_incident_api(incident_id):
        """Add an alert (log entry) to an incident."""
        if not case_storage.get_incident(incident_id):
            return jsonify({"error": "Incident not found"}), 404
        
        data = request.get_json() or {}
        log_id = data.get("log_id")
        
        if not log_id:
            return jsonify({"error": "log_id required"}), 400
        
        added_by = session.get("display_name", "Unknown")
        success = case_storage.add_alert_to_incident(incident_id, log_id, added_by)
        
        if success:
            log_audit_and_emit(
                f"Added alert to incident",
                detail=f"Incident #{incident_id}, alert #{log_id}"
            )
            socketio.emit("alert_added_to_incident", {
                "incident_id": incident_id,
                "log_id": log_id,
            })
            return jsonify({"success": True})
        else:
            return jsonify({"error": "Alert already in incident"}), 409
    
    
    @app.route("/incidents/<int:incident_id>/alerts/<int:log_id>/remove", methods=["DELETE"])
    @analyst_required
    def remove_alert_from_incident_api(incident_id, log_id):
        """Remove an alert from an incident."""
        if not case_storage.get_incident(incident_id):
            return jsonify({"error": "Incident not found"}), 404
        
        case_storage.remove_alert_from_incident(incident_id, log_id)
        
        log_audit_and_emit(
            "Removed alert from incident",
            detail=f"Incident #{incident_id}, alert #{log_id}"
        )
        socketio.emit("alert_removed_from_incident", {
            "incident_id": incident_id,
            "log_id": log_id,
        })
        
        return jsonify({"success": True})
    
    
    # ========================================================================
    # INCIDENT LINKING (RELATIONSHIPS)
    # ========================================================================
    
    @app.route("/incidents/<int:incident_id>/links", methods=["POST"])
    @analyst_required
    def link_incidents_api(incident_id):
        """Create a link between two incidents."""
        if not case_storage.get_incident(incident_id):
            return jsonify({"error": "Incident not found"}), 404
        
        data = request.get_json() or {}
        target_incident_id = data.get("incident_id")
        relation_type = data.get("relation_type", "related")  # related, chain, copied, duplicate
        notes = data.get("notes", "")
        
        if not target_incident_id:
            return jsonify({"error": "incident_id required"}), 400
        if not case_storage.get_incident(target_incident_id):
            return jsonify({"error": "Target incident not found"}), 404
        
        created_by = session.get("display_name", "Unknown")
        success = case_storage.link_incidents(
            incident_id, target_incident_id, relation_type, notes, created_by
        )
        
        if success:
            log_audit_and_emit(
                "Linked incidents",
                detail=f"#{incident_id} -{relation_type}-> #{target_incident_id}"
            )
            socketio.emit("incident_linked", {
                "incident_id_a": incident_id,
                "incident_id_b": target_incident_id,
                "relation_type": relation_type,
            })
            return jsonify({"success": True})
        else:
            return jsonify({"error": "Link already exists"}), 409
    
    
    @app.route("/incidents/<int:incident_id>/links/<int:target_id>/<relation_type>", methods=["DELETE"])
    @analyst_required
    def unlink_incidents_api(incident_id, target_id, relation_type):
        """Remove a link between two incidents."""
        if not case_storage.get_incident(incident_id):
            return jsonify({"error": "Incident not found"}), 404
        
        case_storage.unlink_incidents(incident_id, target_id, relation_type)
        
        log_audit_and_emit(
            "Unlinked incidents",
            detail=f"#{incident_id} -{relation_type}-> #{target_id}"
        )
        socketio.emit("incident_unlinked", {
            "incident_id_a": incident_id,
            "incident_id_b": target_id,
            "relation_type": relation_type,
        })
        
        return jsonify({"success": True})
    
    
    # ========================================================================
    # INCIDENT COMMENTS / COLLABORATION
    # ========================================================================
    
    @app.route("/incidents/<int:incident_id>/comments", methods=["POST"])
    @analyst_required
    def add_comment_api(incident_id):
        """Add a comment to an incident."""
        if not case_storage.get_incident(incident_id):
            return jsonify({"error": "Incident not found"}), 404
        
        data = request.get_json() or {}
        body = data.get("body", "").strip()
        
        if not body:
            return jsonify({"error": "Comment body required"}), 400
        
        author = session.get("display_name", "Unknown")
        comment_id = case_storage.add_comment(incident_id, author, body)
        
        log_audit_and_emit(
            "Commented on incident",
            detail=f"Incident #{incident_id}"
        )
        socketio.emit("comment_added", {
            "incident_id": incident_id,
            "comment_id": comment_id,
            "author": author,
            "body": body,
            "ts": time.time(),
        })
        
        return jsonify({"comment_id": comment_id}), 201
    
    
    @app.route("/incidents/<int:incident_id>/comments/<int:comment_id>", methods=["PUT"])
    @analyst_required
    def update_comment_api(incident_id, comment_id):
        """Update (edit) a comment."""
        if not case_storage.get_incident(incident_id):
            return jsonify({"error": "Incident not found"}), 404
        
        data = request.get_json() or {}
        body = data.get("body", "").strip()
        
        if not body:
            return jsonify({"error": "Comment body required"}), 400
        
        editor = session.get("display_name", "Unknown")
        case_storage.update_comment(comment_id, body, editor)
        
        log_audit_and_emit("Edited comment", detail=f"Incident #{incident_id}, comment #{comment_id}")
        socketio.emit("comment_updated", {
            "incident_id": incident_id,
            "comment_id": comment_id,
            "body": body,
            "edited_ts": time.time(),
            "edited_by": editor,
        })
        
        return jsonify({"success": True})
    
    
    @app.route("/incidents/<int:incident_id>/comments/<int:comment_id>", methods=["DELETE"])
    @analyst_required
    def delete_comment_api(incident_id, comment_id):
        """Delete a comment."""
        if not case_storage.get_incident(incident_id):
            return jsonify({"error": "Incident not found"}), 404
        
        case_storage.delete_comment(comment_id)
        
        log_audit_and_emit("Deleted comment", detail=f"Incident #{incident_id}, comment #{comment_id}")
        socketio.emit("comment_deleted", {
            "incident_id": incident_id,
            "comment_id": comment_id,
        })
        
        return jsonify({"success": True})


# ============================================================================
# SOCKET EVENTS (REAL-TIME UPDATES)
# ============================================================================

def register_case_management_sockets(socketio, case_storage):
    """Register socket event handlers for case management.
    
    Expected signature:
      register_case_management_sockets(socketio, case_storage)
    """
    
    @socketio.on("incident_subscribe")
    def on_incident_subscribe(data):
        """Subscribe to updates for a specific incident."""
        incident_id = (data or {}).get("incident_id")
        if incident_id and case_storage.get_incident(incident_id):
            # Use Flask-SocketIO's own room helpers, which operate on the
            # *current* request's socket connection automatically -- no
            # need (and no safe way) to manually resolve a session id.
            room = f"incident_{incident_id}"
            join_room(room)
    
    
    @socketio.on("incident_unsubscribe")
    def on_incident_unsubscribe(data):
        """Unsubscribe from incident updates."""
        incident_id = (data or {}).get("incident_id")
        if incident_id:
            room = f"incident_{incident_id}"
            leave_room(room)


# ============================================================================
# INTEGRATION INSTRUCTIONS
# ============================================================================
"""
To integrate case management into your Flask app (app.py):

1. IMPORTS: Add to the top of app.py:
   
   import case_management_storage as case_storage
   from case_management_routes import register_case_management_routes, register_case_management_sockets

2. INITIALIZATION: After storage.init_db(), add:
   
   case_storage.init_case_management_db()

3. REGISTER ROUTES: After other route definitions, add:
   
   register_case_management_routes(app, socketio, case_storage, log_audit_and_emit)

4. REGISTER SOCKETS: After other socket handlers, add:
   
   register_case_management_sockets(socketio, case_storage)

That's it! Case management is now wired into your app.
"""