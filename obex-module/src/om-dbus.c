/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2004-2006 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <config.h>
#include <ctype.h>
#include <string.h>
#include <gw-obex.h>
#include <bt-dbus.h>

#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus-glib-lowlevel.h>

#include "om-dbus.h"

/* Just ignore all debug to the STDERR as it's never seen */
#define d(x)

/* Some Bluetooth constants */
#define BLUEZ_DEST		"org.bluez"

#define BLUEZ_ROOT		"/"

#define BLUEZ_ADAPTER		BLUEZ_DEST ".Adapter"
#define BLUEZ_DEVICE		BLUEZ_DEST ".Device"
#define BLUEZ_MANAGER		BLUEZ_DEST ".Manager"
#define BLUEZ_SERIAL		BLUEZ_DEST ".Serial"

#define BLUEZ_RFCOMM		"/dev/rfcomm"
#define BLUEZ_RFCOMM_LEN	11

/* Lock for all manipulations of the devices hash table */
static GMutex     *devices_hash_mutex;
static GHashTable *devices_hash;

/* Gwcond communication. Talks to gwcond to get the device.
 *
 * This API can be accessed from any thread, since it creates it's own context
 * and uses that for the dbus connection.
 */

typedef struct {
	DBusConnection *dbus_conn;
	GMainContext   *context;
	GMainLoop      *loop;
} Connection;

typedef struct {
	gchar *address;
	gboolean paired;
	gboolean blocked;
	gboolean support_ftp;
} DeviceProperties;

/* We will try to disconnect busy devices, but only before they are used, in
 * case they were used while the daemon was killed.
 */
G_LOCK_DEFINE (used_devs);
static GHashTable *used_devs = NULL;

static gboolean get_device_properties (Connection *conn, const char *dev,
				DeviceProperties *devprops,
				gchar *uuid_filter,
				gboolean uuid_filter_prefix);

static void free_device_properties (DeviceProperties *devprops)
{
	if (devprops == NULL)
		return;

	g_free (devprops->address);

	g_free (devprops);
}

static Connection *
get_gwcond_connection (void)
{
	DBusConnection *dbus_conn;
	Connection     *conn;
	DBusError       error;

	/* NOTE: We are using dbus_bus_get_private here, for the reason that
	 * need to get our own private dbus connection to avoid threading
	 * problems with other libraries or applications that use this module
	 * and dbus (the vfs daemon in particular).
	 */
	dbus_error_init (&error);
        dbus_conn = dbus_bus_get_private (DBUS_BUS_SYSTEM, &error);	
	
	if (!dbus_conn) {
		g_printerr ("Failed to connect to the D-BUS daemon: %s", error.message);
		
		dbus_error_free (&error);
		return NULL;
	}

	conn = g_new0 (Connection, 1);
	
	conn->context = g_main_context_new ();
	conn->loop = g_main_loop_new (conn->context, FALSE);

	conn->dbus_conn = dbus_conn;

	dbus_connection_setup_with_g_main (dbus_conn, conn->context);
	
	return conn;
}

void
om_dbus_connection_free (void *dev_conn)
{
	Connection **conn = (Connection **)dev_conn;

	if (conn == NULL || *conn == NULL) {
		return;
	}

	dbus_connection_close ((*conn)->dbus_conn);
	dbus_connection_unref ((*conn)->dbus_conn);
	
	g_main_loop_unref ((*conn)->loop);
	g_main_context_unref ((*conn)->context);
	
	g_free (*conn);
	*conn = NULL;
}

/* Some helpful dbus functions */

static DBusMessage *
get_dbus_message (Connection *conn, const gchar *path, const gchar *intf,
		  const gchar *method)
{
	DBusMessage *msg, *reply;
	DBusError    error;

	msg = dbus_message_new_method_call (BLUEZ_DEST, path, intf, method);
	if (!msg) {
		g_error ("Out of memory");
	}

	dbus_error_init (&error);

	reply = dbus_connection_send_with_reply_and_block (conn->dbus_conn,
							 msg, -1, &error);
	dbus_message_unref (msg);

	if (dbus_error_is_set (&error)) {
		dbus_error_free (&error);

		return NULL;
	}

	return reply;
}

static DBusMessage *
get_dbus_message_param_str (Connection *conn, const gchar *path,
			    const gchar *intf, const gchar *method,
			    const gchar *param)
{
	DBusMessage *msg, *reply;
	DBusError    error;

	msg = dbus_message_new_method_call (BLUEZ_DEST, path, intf, method);
	if (!msg) {
		g_error ("Out of memory");
	}

	if (!dbus_message_append_args (msg,
				       DBUS_TYPE_STRING, &param,
				       DBUS_TYPE_INVALID)) {
		g_error ("Out of memory");
	}

	dbus_error_init (&error);

	reply = dbus_connection_send_with_reply_and_block (conn->dbus_conn,
							 msg, -1, &error);
	dbus_message_unref (msg);

	if (dbus_error_is_set (&error)) {
		dbus_error_free (&error);

		return NULL;
	}

	return reply;
}

/* This assumes that the connection is setup and that the bda has been checked
 * for correctness.
 */
static void
send_cancel_connect (Connection  *conn,
		     const gchar *obj_path,
		     const gchar *bda,
		     const gchar *profile)
{
	DBusMessage *msg;

	d(g_printerr ("obex: Send cancel connect.\n"));
	
	msg = dbus_message_new_method_call (BLUEZ_DEST, obj_path,
					    BLUEZ_SERIAL, "Disconnect");
	if (!msg) {
		g_error ("Out of memory");
	}

	if (!dbus_message_append_args (msg,
				       DBUS_TYPE_STRING, &profile,
				       DBUS_TYPE_INVALID)) {
		g_error ("Out of memory");
	}

	dbus_connection_send (conn->dbus_conn, msg, NULL);
	dbus_message_unref (msg);
}

static void
send_disconnect (Connection *conn,
		 const gchar *obj_path,
		 const gchar *bda,
		 const gchar *str)
{
	DBusMessage *reply;

	d(g_printerr ("obex: Send disconnect.\n"));

	reply = get_dbus_message_param_str (conn, obj_path, BLUEZ_SERIAL,
					    "Disconnect", str);
	if (reply) {
		dbus_message_unref (reply);
	}
}

static gboolean 
send_disconnect_if_first (Connection *conn,
			  const gchar *obj_path,
			  const gchar *bda,
			  const gchar *str)
{
	gchar *lower;
	
	G_LOCK (used_devs);

	if (!used_devs) {
		used_devs = g_hash_table_new (g_str_hash, g_str_equal);
	}

	lower = g_ascii_strdown (bda, -1);
	if (g_hash_table_lookup (used_devs, lower)) {
		g_free (lower);
		d(g_printerr ("obex: %s has already been used, don't disconnect.\n", str));
		G_UNLOCK (used_devs);
		return FALSE;
	}

	d(g_printerr ("obex: %s has not been used yet, disconnect.\n", lower));

	/* The hash table takes ownership of lower here. */
	g_hash_table_insert (used_devs, lower, GINT_TO_POINTER (TRUE));

	G_UNLOCK (used_devs);

	send_disconnect (conn, obj_path, bda, str);

	return TRUE;
}

static gboolean
check_bda (const gchar *bda)
{
	gint len, i;

	if (!bda) {
		return FALSE;
	}

	len = strlen (bda);
	if (len != 17) {
		return FALSE;
	}
	
	for (i = 0; i < 17; i += 3) {
		if (!isxdigit (bda[i])) {
			return FALSE;
		}
		if (!isxdigit (bda[i+1])) {
			return FALSE;
		}
		if (i < 15 && bda[i+2] != ':') {
			return FALSE;
		}
	}
	
	return TRUE;
}

static gchar *
object_path_from_bda (const gchar *bda)
{
	gchar *obj_path;
	gchar *lower = g_ascii_strdown (bda, -1);

	g_mutex_lock (devices_hash_mutex);
	obj_path = g_strdup (g_hash_table_lookup (devices_hash, lower));
	g_mutex_unlock (devices_hash_mutex);
	g_free (lower);

	if (!obj_path) {
		/* TODO: Find the device via DBUS and add it to the hash
 		 * (e.g. recover from gnome-vfs-daemon crash)
 		 */

		if (obj_path) {
			goto success;
		}
	}

success:
	return obj_path;
}

static gboolean
poweron_bluetooth (Connection *conn, const gchar *obj_path)
{
	DBusMessage     *msg;
	DBusMessage     *reply;
	DBusMessageIter  iter, value;
	DBusError        error;
	gchar           *adapter, *ada_path;
	gchar           *prop_name = "Powered";
	gboolean         prop_value = TRUE;

	ada_path = adapter = g_strdup (obj_path);

	if (!adapter || strncmp (adapter, "/org/bluez/", 11))
		return FALSE;

	adapter += 11;

	while (*adapter && isdigit (*adapter))
		++adapter;

	if (*adapter != '/') {
		g_free (ada_path);
		return FALSE;
	}

	++adapter;

	while (*adapter && *adapter != '/')
		++adapter;

	*adapter = '\0';

	msg = dbus_message_new_method_call (BLUEZ_DEST, ada_path,
					    BLUEZ_ADAPTER, "SetProperty");
	if (!msg) {
		g_error ("Out of memory");
	}

	dbus_message_iter_init_append (msg, &iter);
	if (!dbus_message_iter_append_basic (&iter,
				DBUS_TYPE_STRING, &prop_name) ||
			!dbus_message_iter_open_container (&iter,
				DBUS_TYPE_VARIANT, "b", &value) ||
			!dbus_message_iter_append_basic (&value,
				DBUS_TYPE_BOOLEAN, &prop_value) ||
			!dbus_message_iter_close_container (&iter, &value)) {
		g_error ("Out of memory");
	}

	d(g_printerr ("obex: Send power on.\n"));

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (conn->dbus_conn,
							   msg, -1, &error);
	
	dbus_message_unref (msg);

	if (dbus_error_is_set (&error)) {
		g_warning ("Error power on adapter (%s): %s: %s", ada_path,
				error.name, error.message);

		dbus_error_free (&error);
		return FALSE;
	}
	
	if (!reply) {
		return FALSE;
	}

	dbus_message_unref (reply);

	return TRUE;
}

static DBusMessage *
get_list_adapters (Connection *conn)
{
	return get_dbus_message (conn, BLUEZ_ROOT, BLUEZ_MANAGER,
				 "ListAdapters");
}

static DBusMessage *
get_list_devices (Connection *conn, gchar *adaname)
{
	return get_dbus_message (conn, adaname, BLUEZ_ADAPTER,
				 "ListDevices");
}

static gboolean
get_dict_property (DBusMessageIter *sub,
		   DeviceProperties *devprops,
		   char *uuid_filter,
		   gboolean uuid_filter_prefix)
{
	DBusMessageIter dict_entry, dict_value;
	gchar *dict_key, *dict_str = NULL;

	if (dbus_message_iter_get_arg_type (sub) != DBUS_TYPE_DICT_ENTRY) {
		return FALSE;
	}

	dbus_message_iter_recurse (sub, &dict_entry);

	/* Try to get the Key */
	dbus_message_iter_get_basic (&dict_entry, &dict_key);
	if (dict_key == NULL) {
		return FALSE;
	}

	/* Go to the value */
	if (!dbus_message_iter_next (&dict_entry)) {
		return FALSE;
	}

	/* Try to get the value */
	if (dbus_message_iter_get_arg_type (&dict_entry) != DBUS_TYPE_VARIANT) {
		return FALSE;
	}

	/* Go to the Variant */
	dbus_message_iter_recurse (&dict_entry, &dict_value);

	if (!g_strcmp0 (dict_key, "Address")) {
		dbus_message_iter_get_basic (&dict_value, &dict_str);
		devprops->address = g_strdup (dict_str);
	} else if (!g_strcmp0 (dict_key, "Paired")) {
		dbus_message_iter_get_basic (&dict_value, &devprops->paired);
	} else if (!g_strcmp0 (dict_key, "Blocked")) {
		dbus_message_iter_get_basic (&dict_value, &devprops->blocked);
	} else if (!g_strcmp0 (dict_key, "UUIDs")) {
		DBusMessageIter uuid_entry;

		if (uuid_filter == NULL || *uuid_filter == '\0') {
			devprops->support_ftp = TRUE;
			goto next;
		}

		/* Go to the array of UUIDs */
		dbus_message_iter_recurse (&dict_value, &uuid_entry);

		do {
			dbus_message_iter_get_basic (&uuid_entry, &dict_str);
			if ((!uuid_filter_prefix &&
					!g_strcmp0 (uuid_filter, dict_str)) ||
			    (uuid_filter_prefix &&
					g_str_has_prefix (dict_str, uuid_filter))) {
				devprops->support_ftp = TRUE;
				goto next;

			}
		} while (dbus_message_iter_next (&uuid_entry));

		devprops->support_ftp = FALSE;
	}

next:
	return TRUE;
}

/* Note: This needs to be refactored for the next version, we need our own
 * return value here, which can include invalid profile and already connected as
 * results. We can also move the bda checking to the caller, it only needs
 * checked once.
 */
static gchar *
get_dev (Connection     *conn,
	 const gchar    *obj_path,
	 const gchar    *bda,
	 const gchar    *profile,
	 GnomeVFSResult *result,
	 gboolean       *invalid_profile,
	 gboolean       *already_connected)
{
	DBusMessage     *msg, *reply;
	DBusMessageIter  iter;
	DBusError        error;
	gchar           *str;
	gchar           *dev;

	*result = GNOME_VFS_OK;
	*invalid_profile = FALSE;
	*already_connected = FALSE;
	
	msg = dbus_message_new_method_call (BLUEZ_DEST, obj_path,
						BLUEZ_SERIAL, "Connect");
	if (!msg) {
		g_error ("Out of memory");
	}

	if (!dbus_message_append_args (msg,
				       DBUS_TYPE_STRING, &profile,
				       DBUS_TYPE_INVALID)) {
		g_error ("Out of memory");
	}

connect:
	d(g_printerr ("obex: Send connect.\n"));

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (conn->dbus_conn,
							   msg, -1, &error);
	
	/* The errors according to the bluez 4.X:
	 *
	 * org.bluez.Error.ConnectionAttemptFailed
	 * org.bluez.Error.DoesNotExist
	 * org.bluez.Error.Failed
	 * org.bluez.Error.InProgress
	 * org.bluez.Error.InvalidArguments
	 * org.bluez.Error.NotSupported
	 * org.bluez.Error.UnknownMethod
	 */

	if (dbus_error_is_set (&error)) {
		g_warning ("Error connecting to remote device (%s): %s: %s",
				obj_path, error.name, error.message);

		if (g_strcmp0 (error.name, "org.bluez.Error.DoesNotExist") == 0 ||
		    g_strcmp0 (error.name, "org.bluez.Error.InvalidArguments") == 0) {
			d(g_printerr ("obex: Invalid SDP profile.\n"));
			*result = GNOME_VFS_ERROR_SERVICE_NOT_AVAILABLE;
			*invalid_profile = TRUE;
		}
		else if (g_strcmp0 (error.name, "org.bluez.Error.UnknownMethod") == 0) {
			d(g_printerr ("obex: Invalid BDA.\n"));
			*result = GNOME_VFS_ERROR_SERVICE_NOT_AVAILABLE;
		}
		else if (g_strcmp0 (error.name, "org.bluez.Error.ConnectionAttemptFailed") == 0) {
			d(g_printerr ("obex: GW connect failed.\n"));
			*result = GNOME_VFS_ERROR_SERVICE_NOT_AVAILABLE;
			// TODO: needs to be investigated when to set
			//*already_connected = TRUE;
		}
		else if (g_strcmp0 (error.name, "org.bluez.Error.Failed") == 0) {
			/* Check if adapter is powered on */
			if (!g_strcmp0 (error.message, "No route to host")) {
				dbus_error_free (&error);
				if (poweron_bluetooth (conn, obj_path))
					goto connect;
			}
			d(g_printerr ("obex: GW connect failed.\n"));
			*result = GNOME_VFS_ERROR_SERVICE_NOT_AVAILABLE;
		}
		else if (g_strcmp0 (error.name, DBUS_ERROR_NAME_HAS_NO_OWNER) == 0 ||
			 g_strcmp0 (error.name, DBUS_ERROR_SERVICE_UNKNOWN) == 0) {
			d(g_printerr ("obex: bluetoothd is not running.\n"));
			*result = GNOME_VFS_ERROR_SERVICE_NOT_AVAILABLE;
		}
		else if (g_strcmp0 (error.name, DBUS_ERROR_NO_REPLY) == 0 ||
			 g_strcmp0 (error.name, "org.bluez.Error.InProgress")) {
			d(g_printerr ("obex: No reply.\n"));
			/* We get this when bluetoothd times out. Cancel the
			 * connection so that btcond knows that this end will
			 * not be interested in the connection if we time out.
			 */
			send_cancel_connect (conn, obj_path, bda, profile);
			
			*result = GNOME_VFS_ERROR_SERVICE_NOT_AVAILABLE;
		} else {
			d(g_printerr ("obex: generic '%s'\n", error.name));
			*result = GNOME_VFS_ERROR_INTERNAL;
		}

		dbus_message_unref (msg);
		dbus_error_free (&error);
		return NULL;
	}
	
	dbus_message_unref (msg);

	if (!reply) {
		*result = GNOME_VFS_ERROR_SERVICE_NOT_AVAILABLE;
		return NULL;
	}

	if (!dbus_message_iter_init (reply, &iter) ||
	    dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_STRING) {
		dbus_message_unref (reply);
		*result = GNOME_VFS_ERROR_SERVICE_NOT_AVAILABLE;
		return NULL;
	}

	dbus_message_iter_get_basic (&iter, &str);
	dev = g_strdup (str);
	dbus_message_unref (reply);
	*result = GNOME_VFS_OK;

	return dev;
}

void
om_dbus_init (void)
{
	devices_hash_mutex = g_mutex_new ();
	devices_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
						g_free, g_free);
}

void
om_dbus_shutdown (void)
{
	g_mutex_lock (devices_hash_mutex);
	g_hash_table_remove_all (devices_hash);
	g_hash_table_destroy (devices_hash);
	devices_hash = NULL;
	g_mutex_unlock (devices_hash_mutex);
	g_mutex_free (devices_hash_mutex);
}

gchar *
om_dbus_get_dev (void *dev_conn,
		 const gchar *bda,
		 GnomeVFSResult *result)
{
	Connection  **device_conn = (Connection  **)dev_conn;
	Connection  *conn;
	const gchar *profile;
	gchar       *dev = NULL;
	gchar       *obj_path;
	gboolean     invalid_profile;
	gboolean     already_connected;

	if (bda && !strncmp (bda, BLUEZ_RFCOMM, BLUEZ_RFCOMM_LEN)) {
		return g_strdup (bda);
	}

	if (!device_conn) {
		*result = GNOME_VFS_ERROR_SERVICE_NOT_AVAILABLE;
		return NULL;
	}

	conn = get_gwcond_connection ();
	if (!conn) {
		*result = GNOME_VFS_ERROR_SERVICE_NOT_AVAILABLE;
		return NULL;
	}
	
	if (!check_bda (bda)) {
		*result = GNOME_VFS_ERROR_INVALID_URI;
		goto free_dev;
	}

	obj_path = object_path_from_bda (bda);
	if (!obj_path) {
		*result = GNOME_VFS_ERROR_INVALID_URI;
		goto free;
	}

	/* Try NFTP first, which appears to be some vendor specific profile. If
	 * it's not available, fallback to FTP.
	 */

	profile = "NFTP";
	dev = get_dev (conn, obj_path, bda, profile, result,
		       &invalid_profile, &already_connected);
	if (!dev && invalid_profile) {
		profile = "FTP";
		dev = get_dev (conn, obj_path, bda, profile, result,
			       &invalid_profile, &already_connected);
	}

	/* We only try to disconnect once, when first starting, in case there
	 * are old stale connections.
	 */
	if (!dev && already_connected) {
		if (send_disconnect_if_first (conn, obj_path, bda, profile)) {
			dev = get_dev (conn, obj_path, bda, profile, result,
				       &invalid_profile, &already_connected);
		}
	}
	
free:
	g_free (obj_path);

free_dev:
	if (dev) {
		*device_conn = conn;
	} else {
		om_dbus_connection_free (&conn);
	}
	
	return dev;
}

void
om_dbus_disconnect_dev (void *dev_conn, const gchar *bda, const gchar *dev)
{
	Connection **conn = (Connection **)dev_conn;
	gchar *obj_path;

	if (!conn || !*conn || !bda ||
	    !strncmp (bda, BLUEZ_RFCOMM, BLUEZ_RFCOMM_LEN)) {
		return;
	}
	
	obj_path = object_path_from_bda (bda);
	if (obj_path) {
		send_disconnect (*conn, obj_path, bda, dev);
		g_free (obj_path);
	}

	om_dbus_connection_free (conn);
}

static void
om_append_paired_devices (Connection   *conn, 
			  DBusMessage  *msg,
                          const char   *devname, 
			  GList       **list)
{
        DBusMessageIter diter;
	DBusMessageIter dsub;
	DeviceProperties *devprops;

        if (!dbus_message_iter_init (msg, &diter)) {
		return;
	}

	dbus_message_iter_recurse (&diter, &dsub);
	
	do { 
		/* Add the entry to the list. */
		GnomeVFSFileInfo *info;
		char             *remote_devname;
		
		if (dbus_message_iter_get_arg_type (&dsub) != DBUS_TYPE_OBJECT_PATH) {
			continue;
		}
		
		dbus_message_iter_get_basic (&dsub, &remote_devname);
		
		devprops = g_new0 (DeviceProperties, 1);
		if (devprops == NULL)
			g_error ("Out of memory");

		/* Question: do we need whole UUID?
		 * "00001106-0000-1000-8000-00805f9b34fb" */
		if (!get_device_properties (conn, (const char*) remote_devname,
				       	devprops, "00001106-", TRUE)) {
			free_device_properties (devprops);
			continue;
		}
		if (!devprops->paired || devprops->blocked ||
				!devprops->support_ftp) {
			free_device_properties (devprops);
			continue;
		}
		
		info = gnome_vfs_file_info_new ();
		
		if (!info) {
			free_device_properties (devprops);
			return;
		}
		
		info->flags |= GNOME_VFS_FILE_FLAGS_SYMLINK;
		
		info->valid_fields = 
			GNOME_VFS_FILE_INFO_FIELDS_TYPE |
			GNOME_VFS_FILE_INFO_FIELDS_PERMISSIONS |
			GNOME_VFS_FILE_INFO_FIELDS_MIME_TYPE |
			GNOME_VFS_FILE_INFO_FIELDS_SYMLINK_NAME;
		
		info->name = g_strdup_printf ("[%s]", devprops->address);
		info->type = GNOME_VFS_FILE_TYPE_SYMBOLIC_LINK;
		info->permissions = 
			GNOME_VFS_PERM_USER_READ |
			GNOME_VFS_PERM_GROUP_READ |
			GNOME_VFS_PERM_OTHER_READ;
		
		info->uid = 0;
		info->gid = 0;
		info->mime_type = g_strdup ("x-directory/normal");

		info->symlink_name = g_strdup_printf ("obex://[%s]", devprops->address);

		/*g_print ("added name: %s, symlink name: %s\n", info->name, info->symlink_name);*/
		
		if (!info->symlink_name) {
			/* Extra caution. */
			gnome_vfs_file_info_unref (info);
			free_device_properties (devprops);
			continue;
		}

		*list = g_list_append (*list, info);
		g_hash_table_insert (devices_hash,
				g_ascii_strdown (devprops->address, -1),
				g_strdup (remote_devname));

		free_device_properties (devprops);
	} while (dbus_message_iter_next (&dsub));
}

/* Leave this in for easy testing. */
#if 0
static GList *
append_fake_device (GList *list, const gchar *bda)
{
	GnomeVFSFileInfo *info;
	
	info = gnome_vfs_file_info_new ();
	
	info->valid_fields = 
		GNOME_VFS_FILE_INFO_FIELDS_TYPE |
		GNOME_VFS_FILE_INFO_FIELDS_PERMISSIONS |
		GNOME_VFS_FILE_INFO_FIELDS_MIME_TYPE |
		GNOME_VFS_FILE_INFO_FIELDS_SYMLINK_NAME;
	
	info->flags |= GNOME_VFS_FILE_FLAGS_SYMLINK;
	
	info->name = g_strdup_printf ("[%s]", bda);
	info->type = GNOME_VFS_FILE_TYPE_SYMBOLIC_LINK;
	info->permissions = 
		GNOME_VFS_PERM_USER_READ |
		GNOME_VFS_PERM_GROUP_READ |
		GNOME_VFS_PERM_OTHER_READ;
	info->symlink_name = g_strdup_printf ("obex://[%s]", bda);
		
	info->uid = 0;
	info->gid = 0;
	info->mime_type = g_strdup ("x-directory/normal");

	/*g_print ("added fake: %s %s\n", info->name, info->symlink_name);*/

	return g_list_append (list, info);
}
#endif

GList *
om_dbus_get_dev_list (void)
{
	Connection      *conn;
	DBusMessage     *reply_ada;
        DBusMessageIter  iter;
	GList           *devlist = NULL;

#if 0
	if (0) {
		devlist = append_fake_device (devlist, "foo");
		devlist = append_fake_device (devlist, "bar");
		
		return devlist;
	}
#endif
	
	conn = get_gwcond_connection ();
	if (!conn) {
		return NULL;
	}

	reply_ada = get_list_adapters (conn);
	if (!reply_ada) {
		om_dbus_connection_free (&conn);
		return NULL;
	}

	if (dbus_message_iter_init (reply_ada, &iter)) {
                DBusMessageIter sub;

		dbus_message_iter_recurse (&iter, &sub);

		g_mutex_lock (devices_hash_mutex);
		g_hash_table_remove_all (devices_hash);

		/* Go through each entry (device) and get each paired device
		 * from the entry.
		 */
		do {
			char *adapath;
			DBusMessage *reply_dev;

			dbus_message_iter_get_basic (&sub, &adapath);

			reply_dev = get_list_devices (conn, adapath);
			if (!reply_dev) {
				continue;
			}

			om_append_paired_devices (conn, reply_dev, adapath,
						  &devlist);

			dbus_message_unref (reply_dev);
			
		} while (dbus_message_iter_next (&sub));

		g_mutex_unlock (devices_hash_mutex);
	}

	dbus_message_unref (reply_ada);

	om_dbus_connection_free (&conn);

	return devlist;
}

static gboolean
get_device_properties (Connection *conn, const char *dev,
		DeviceProperties *devprops, char *uuid_filter,
		gboolean uuid_filter_prefix)
{
	DBusMessage      *reply;
	DBusMessageIter  iter, sub;

	reply = get_dbus_message (conn, dev, BLUEZ_DEVICE, "GetProperties");
	if (!reply) {
		return FALSE;
	}

	if (dbus_message_iter_init (reply, &iter)) {

		dbus_message_iter_recurse (&iter, &sub);

		while (get_dict_property (&sub, devprops, uuid_filter,
				uuid_filter_prefix) &&
				dbus_message_iter_next (&sub)) {
		}
	}

	dbus_message_unref (reply);

	return devprops->address != NULL;
}

