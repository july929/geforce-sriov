// SPDX-License-Identifier: MIT
/*
 * report: everything a compatibility report asks for, in one block with private details removed.
 *
 * It reads /sys, /proc and the package's own status and host checks. The only programs it runs are
 * lspci (names of the PCI devices), journalctl (the kernel log), nvidia-smi (the VRAM size, present
 * with NVIDIA's driver) and, when the host has them, pveversion, virsh and qemu-system-x86_64. A
 * program that is not there leaves its field out, and the block says so.
 */
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "gs_hook.h"
#include "gs_lifecycle.h"
#include "gs_internal.h"

/* ---- text buffer -------------------------------------------------------- */

struct sbuf {
	char *p;
	size_t len, cap;
};

static void sb_put(struct sbuf *b, const char *s, size_t n)
{
	if (b->len + n + 1 > b->cap) {
		size_t cap = b->cap ? b->cap : 4096;
		char *np;

		while (cap < b->len + n + 1)
			cap *= 2;
		np = realloc(b->p, cap);
		if (!np) {
			perror("geforce-sriov: report");
			exit(GS_EXIT_FAIL);
		}
		b->p = np;
		b->cap = cap;
	}
	memcpy(b->p + b->len, s, n);
	b->len += n;
	b->p[b->len] = '\0';
}

static void sb_str(struct sbuf *b, const char *s)
{
	sb_put(b, s, strlen(s));
}

static void sb_printf(struct sbuf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void sb_printf(struct sbuf *b, const char *fmt, ...)
{
	char tmp[2048];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	sb_put(b, tmp, (size_t)n < sizeof(tmp) ? (size_t)n : sizeof(tmp) - 1);
}

/* ---- redaction ---------------------------------------------------------- */

void gs_redactor_init(struct gs_redactor *r)
{
	memset(r, 0, sizeof(*r));
}

/* Not a name of this host or its people: the loopback name, the host name a system has before it is set, and service accounts. */
static int common_name(const char *s)
{
	static const char *const common[] = { "localhost", "(none)", "root", "nobody", NULL };

	for (size_t i = 0; common[i]; i++)
		if (strcasecmp(s, common[i]) == 0)
			return 1;
	return 0;
}

static void add_name(char (*list)[64], unsigned int *n, const char *name)
{
	if (!name || strlen(name) < 2 || strlen(name) >= 64 || common_name(name))
		return;
	for (unsigned int i = 0; i < *n; i++)
		if (strcasecmp(list[i], name) == 0)
			return;
	if (*n < GS_REDACT_NAMES)
		gs_copy(list[(*n)++], 64, name);
}

void gs_redactor_add_host(struct gs_redactor *r, const char *name)
{
	char *dot;
	char first[64];

	add_name(r->host, &r->nhost, name);
	if (name && (dot = strchr(name, '.')) && dot > name) {
		snprintf(first, sizeof(first), "%.*s", (int)(dot - name), name);
		add_name(r->host, &r->nhost, first);
	}
}

void gs_redactor_add_user(struct gs_redactor *r, const char *name)
{
	add_name(r->user, &r->nuser, name);
}

/* The host name and the accounts of this machine: people, not services. */
void gs_redactor_collect(struct gs_redactor *r)
{
	char host[256];
	struct passwd *pw;
	const char *e;

	if (gethostname(host, sizeof(host) - 1) == 0) {
		host[sizeof(host) - 1] = '\0';
		gs_redactor_add_host(r, host);
	}
	if ((e = getenv("SUDO_USER")))
		gs_redactor_add_user(r, e);
	if ((e = getenv("USER")))
		gs_redactor_add_user(r, e);
	if ((e = getenv("LOGNAME")))
		gs_redactor_add_user(r, e);
	setpwent();
	while ((pw = getpwent()))
		if (pw->pw_uid >= 1000 && pw->pw_uid < 60000)
			gs_redactor_add_user(r, pw->pw_name);
	endpwent();
}

static int is_hex(char c)
{
	return isxdigit((unsigned char)c) != 0;
}

static int is_alnum(char c)
{
	return isalnum((unsigned char)c) != 0;
}

static int hex_run(const char *s, size_t n, size_t want)
{
	if (n < want)
		return 0;
	for (size_t i = 0; i < want; i++)
		if (!is_hex(s[i]))
			return 0;
	return 1;
}

/* GPU-/MIG- prefix optional, then 8-4-4-4-12 hex digits. */
static size_t match_uuid(const char *s, size_t n)
{
	static const size_t parts[] = { 8, 4, 4, 4, 12 };
	size_t i = 0;

	if (n > 4 && (strncmp(s, "GPU-", 4) == 0 || strncmp(s, "MIG-", 4) == 0))
		i = 4;
	for (size_t k = 0; k < 5; k++) {
		if (k) {
			if (i >= n || s[i] != '-')
				return 0;
			i++;
		}
		if (!hex_run(s + i, n - i, parts[k]))
			return 0;
		i += parts[k];
	}
	if (i < n && is_alnum(s[i]))
		return 0;
	return i;
}

static size_t match_mac(const char *s, size_t n)
{
	char sep;

	if (n < 17 || (s[2] != ':' && s[2] != '-'))
		return 0;
	sep = s[2];
	for (size_t k = 0; k < 6; k++) {
		if (!hex_run(s + 3 * k, n - 3 * k, 2))
			return 0;
		if (k < 5 && s[3 * k + 2] != sep)
			return 0;
	}
	if (n > 17 && (is_hex(s[17]) || (s[17] == sep && n > 18 && is_hex(s[18]))))
		return 0;
	return 17;
}

static size_t match_ipv4(const char *s, size_t n)
{
	size_t i = 0;

	for (int k = 0; k < 4; k++) {
		unsigned int v = 0, d = 0;

		if (k) {
			if (i >= n || s[i] != '.')
				return 0;
			i++;
		}
		while (i < n && isdigit((unsigned char)s[i]) && d < 4) {
			v = v * 10 + (unsigned int)(s[i] - '0');
			i++;
			d++;
		}
		if (d == 0 || d > 3 || v > 255)
			return 0;
	}
	if (i < n && (isdigit((unsigned char)s[i]) || (s[i] == '.' && i + 1 < n && isdigit((unsigned char)s[i + 1]))))
		return 0;
	return i;
}

static size_t match_ipv6(const char *s, size_t n)
{
	size_t i = 0;
	int groups = 0, dbl = 0;

	if (n >= 2 && s[0] == ':' && s[1] == ':') {
		dbl = 1;
		i = 2;
	} else if (n && s[0] == ':') {
		return 0;
	}
	for (;;) {
		size_t j = i;

		while (j < n && is_hex(s[j]))
			j++;
		if (j == i)
			break;
		if (j - i > 4)
			return 0;
		groups++;
		i = j;
		if (i + 1 < n && s[i] == ':' && s[i + 1] == ':') {
			if (dbl)
				return 0;
			dbl = 1;
			i += 2;
			continue;
		}
		if (i + 1 < n && s[i] == ':' && is_hex(s[i + 1])) {
			i++;
			continue;
		}
		break;
	}
	if (groups == 0 || (dbl ? groups > 7 : groups != 8))
		return 0;
	if (i < n && (is_alnum(s[i]) || s[i] == ':' || (s[i] == '.' && i + 1 < n && isdigit((unsigned char)s[i + 1]))))
		return 0;
	return i;
}

static int name_boundary(char c)
{
	return is_alnum(c) || c == '_' || c == '-';
}

/* The longest listed name at s; 0 when none. */
static size_t match_name(const char (*list)[64], unsigned int count, const char *s, size_t n)
{
	size_t best = 0;

	for (unsigned int k = 0; k < count; k++) {
		size_t l = strlen(list[k]);

		if (l > best && l <= n && strncasecmp(s, list[k], l) == 0 && (l == n || !name_boundary(s[l])))
			best = l;
	}
	return best;
}

/* One piece of a line, scanned for the address-like and name-like details. */
static void redact_span(struct gs_redactor *r, struct sbuf *o, const char *s, size_t n)
{
	size_t i = 0;

	while (i < n) {
		size_t m = 0;
		const char *rep = NULL;
		int boundary = i == 0 || !is_alnum(s[i - 1]);
		int name_ok = i == 0 || !name_boundary(s[i - 1]);

		if (boundary) {
			if ((m = match_uuid(s + i, n - i))) {
				rep = "<uuid>";
				r->n_uuid++;
			} else if ((m = match_mac(s + i, n - i))) {
				rep = "<mac>";
				r->n_mac++;
			} else if ((m = match_ipv6(s + i, n - i)) && (i == 0 || (s[i - 1] != ':' && s[i - 1] != '.'))) {
				rep = "<ip>";
				r->n_ip++;
			} else if ((m = match_ipv4(s + i, n - i)) && (i == 0 || (s[i - 1] != '.' && !isdigit((unsigned char)s[i - 1])))) {
				rep = "<ip>";
				r->n_ip++;
			} else {
				m = 0;
			}
		}
		if (!m && name_ok) {
			if ((m = match_name(r->host, r->nhost, s + i, n - i))) {
				rep = "<hostname>";
				r->n_name++;
			} else if ((m = match_name(r->user, r->nuser, s + i, n - i))) {
				rep = "<user>";
				r->n_name++;
			}
		}
		if (m) {
			sb_str(o, rep);
			i += m;
		} else {
			sb_put(o, s + i, 1);
			i++;
		}
	}
}

static const char *ci_find(const char *s, size_t n, const char *needle)
{
	size_t l = strlen(needle);

	for (size_t i = 0; i + l <= n; i++)
		if (strncasecmp(s + i, needle, l) == 0)
			return s + i;
	return NULL;
}

static void redact_line(struct gs_redactor *r, struct sbuf *o, const char *s, size_t n)
{
	const char *p;

	if (ci_find(s, n, "token") || ci_find(s, n, "license server") || ci_find(s, n, "licence server") ||
	    ci_find(s, n, "serveraddress") || ci_find(s, n, "featuretype") || ci_find(s, n, "gridd.conf")) {
		sb_str(o, "<licence line removed>");
		r->n_licence++;
		return;
	}
	if ((p = ci_find(s, n, "serial"))) {
		size_t k = (size_t)(p - s) + 6;

		while (k < n && s[k] != ':' && s[k] != '=')
			k++;
		if (k < n) {
			redact_span(r, o, s, k + 1);
			sb_str(o, " <serial removed>");
		} else {
			sb_str(o, "<serial line removed>");
		}
		r->n_serial++;
		return;
	}
	redact_span(r, o, s, n);
}

char *gs_redact(struct gs_redactor *r, const char *text)
{
	struct sbuf o = { 0 };
	const char *s = text;

	sb_put(&o, "", 0);
	while (*s) {
		const char *nl = strchr(s, '\n');
		size_t n = nl ? (size_t)(nl - s) : strlen(s);

		redact_line(r, &o, s, n);
		if (nl)
			sb_put(&o, "\n", 1);
		s += n + (nl ? 1 : 0);
	}
	return o.p;
}

/* ---- kernel log --------------------------------------------------------- */

#define LOG_LINE_MAX 300

/* The last max lines of log that name geforce_sriov, NVRM or AER; omitted counts the earlier matches. */
char *gs_report_log_filter(const char *log, unsigned int max, unsigned int *omitted)
{
	struct sbuf o = { 0 };
	const char *s = log;
	unsigned int total = 0, skip = 0, seen = 0;

	sb_put(&o, "", 0);
	for (int pass = 0; pass < 2; pass++) {
		s = log;
		while (*s) {
			const char *nl = strchr(s, '\n');
			size_t n = nl ? (size_t)(nl - s) : strlen(s);

			if (ci_find(s, n, "geforce_sriov") || memmem(s, n, "NVRM", 4) || memmem(s, n, "AER", 3)) {
				if (pass == 0) {
					total++;
				} else if (seen++ >= skip) {
					sb_put(&o, s, n < LOG_LINE_MAX ? n : LOG_LINE_MAX);
					sb_put(&o, "\n", 1);
				}
			}
			s += n + (nl ? 1 : 0);
		}
		skip = total > max ? total - max : 0;
	}
	*omitted = total > max ? total - max : 0;
	return o.p;
}

/* ---- collection --------------------------------------------------------- */

static int read_text(const char *path, char *buf, size_t len)
{
	return gs_read_attr(path, buf, len) == 0 && buf[0];
}

static int os_release_value(const char *key, char *out, size_t len)
{
	char *data, *line, *save = NULL;
	size_t dl, kl = strlen(key);
	int found = 0;

	out[0] = '\0';
	if (gs_read_whole("/etc/os-release", &data, &dl, 1 << 16) && gs_read_whole("/usr/lib/os-release", &data, &dl, 1 << 16))
		return 0;
	for (line = strtok_r(data, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		if (strncmp(line, key, kl) == 0 && line[kl] == '=') {
			const char *v = line + kl + 1;
			size_t n = strlen(v);

			if (n >= 2 && (v[0] == '"' || v[0] == '\'')) {
				v++;
				n -= 2;
			}
			snprintf(out, len, "%.*s", (int)n, v);
			found = 1;
			break;
		}
	}
	free(data);
	return found;
}

/* The first line of a program's output; 0 when the program is missing or prints nothing. */
static int first_line(const char *const argv[], char *out, size_t len)
{
	char buf[1024], *nl;

	if (gs_run_capture(argv, buf, sizeof(buf)) != 0 || !buf[0])
		return 0;
	if ((nl = strchr(buf, '\n')))
		*nl = '\0';
	gs_copy(out, len, buf);
	return 1;
}

static void put_hypervisors(struct sbuf *b)
{
	char line[256];
	int any = 0;
	const char *pve[] = { "pveversion", NULL };
	const char *virsh[] = { "virsh", "--version", NULL };
	const char *qemu[] = { "qemu-system-x86_64", "--version", NULL };

	if (first_line(pve, line, sizeof(line))) {
		sb_printf(b, "hypervisor: Proxmox VE, %s\n", line);
		any = 1;
	}
	if (first_line(virsh, line, sizeof(line))) {
		sb_printf(b, "hypervisor: libvirt %s\n", line);
		any = 1;
	}
	if (first_line(qemu, line, sizeof(line))) {
		sb_printf(b, "hypervisor: %s\n", line);
		any = 1;
	}
	if (!any)
		sb_str(b, "hypervisor: none found (pveversion, virsh and qemu-system-x86_64 are not installed)\n");
}

static void put_dmi(struct sbuf *b, const char *sys)
{
	static const struct { const char *file, *label; } f[] = {
		{ "sys_vendor", "system vendor" }, { "product_name", "system product" }, { "board_vendor", "board vendor" },
		{ "board_name", "board" }, { "bios_vendor", "firmware vendor" }, { "bios_version", "firmware version" },
		{ "bios_date", "firmware date" },
	};
	int any = 0;

	for (size_t i = 0; i < sizeof(f) / sizeof(f[0]); i++) {
		char p[GS_PATH_MAX], v[128];

		if (!gs_pathf(p, sizeof(p), "%s/class/dmi/id/%s", sys, f[i].file) && read_text(p, v, sizeof(v))) {
			sb_printf(b, "%s: %s\n", f[i].label, v);
			any = 1;
		}
	}
	if (!any)
		sb_str(b, "board and firmware: not readable\n");
}

static unsigned int count_dir(const char *path)
{
	DIR *d = opendir(path);
	struct dirent *de;
	unsigned int n = 0;

	if (!d)
		return 0;
	while ((de = readdir(d)))
		if (de->d_name[0] != '.')
			n++;
	closedir(d);
	return n;
}

/* The options of the kernel command line that decide IOMMU, PCIe and resource assignment. */
static void put_cmdline(struct sbuf *b, const char *proc)
{
	char p[GS_PATH_MAX], *data, *tok, *save = NULL, rel[2048] = "";
	size_t len;

	if (gs_pathf(p, sizeof(p), "%s/cmdline", proc) || gs_read_whole(p, &data, &len, 1 << 16)) {
		sb_str(b, "kernel command line: not readable\n");
		return;
	}
	while (len && (data[len - 1] == '\n' || data[len - 1] == ' '))
		data[--len] = '\0';
	sb_printf(b, "kernel command line: %s\n", data);
	for (tok = strtok_r(data, " \t\n", &save); tok; tok = strtok_r(NULL, " \t\n", &save))
		if (strstr(tok, "iommu") || strncmp(tok, "pci=", 4) == 0 || strncmp(tok, "pcie_", 5) == 0 ||
		    strncmp(tok, "vfio", 4) == 0 || strncmp(tok, "nvidia", 6) == 0) {
			if (strlen(rel) + strlen(tok) + 2 < sizeof(rel))
				strcat(strcat(rel, rel[0] ? " " : ""), tok);
		}
	sb_printf(b, "IOMMU and PCIe options on the command line: %s\n", rel[0] ? rel : "none");
	free(data);
}

static int read_u64(const char *s, unsigned long long *v)
{
	char *end;

	*v = strtoull(s, &end, 16);
	return end != s;
}

/* BAR lines of <pf>/resource: the first 64-bit memory BAR above 4 GiB tells that Above 4G decoding is on. */
static void put_bars(struct sbuf *b, const char *devdir, int *above)
{
	char p[GS_PATH_MAX], *data, *line, *save = NULL;
	size_t len;
	int idx = 0;

	if (gs_pathf(p, sizeof(p), "%s/resource", devdir) || gs_read_whole(p, &data, &len, 1 << 16)) {
		sb_str(b, "  BARs: not readable\n");
		return;
	}
	for (line = strtok_r(data, "\n", &save); line && idx < 7; line = strtok_r(NULL, "\n", &save), idx++) {
		unsigned long long s = 0, e = 0, fl = 0;
		char *q = line;

		if (idx != 0 && idx != 1 && idx != 3)
			continue;
		if (!read_u64(q, &s))
			continue;
		q = strchr(q, ' ');
		if (!q || !read_u64(q + 1, &e) || !(q = strchr(q + 1, ' ')) || !read_u64(q + 1, &fl) || s == 0)
			continue;
		sb_printf(b, "  BAR%d: start 0x%llx, size %llu MiB%s\n", idx, s, (e - s + 1) >> 20, s > 0xffffffffull ? ", above 4 GiB" : "");
		if (s > 0xffffffffull)
			*above = 1;
	}
	free(data);
}

static void lspci_name(const char *bdf, char *out, size_t len)
{
	char buf[512], *sp, *nl;
	const char *argv[] = { "lspci", "-nn", "-s", bdf, NULL };

	out[0] = '\0';
	if (gs_run_capture(argv, buf, sizeof(buf)) != 0 || !buf[0])
		return;
	if ((nl = strchr(buf, '\n')))
		*nl = '\0';
	sp = strchr(buf, ' ');
	gs_copy(out, len, sp ? sp + 1 : buf);
}

/* The bridges from the root port down to the GPU, from the resolved sysfs path of the device. */
static void put_path(struct sbuf *b, const char *sys, const struct gs_addr *pf, int live)
{
	char link[GS_PATH_MAX], real[PATH_MAX], *comp, *save = NULL;
	struct gs_addr chain[16];
	unsigned int n = 0;

	if (gs_pathf(link, sizeof(link), "%s/bus/pci/devices/%s", sys, pf->str) || !realpath(link, real)) {
		sb_str(b, "  PCIe path: not readable\n");
		return;
	}
	for (comp = strtok_r(real, "/", &save); comp; comp = strtok_r(NULL, "/", &save)) {
		struct gs_addr a;

		if (gs_addr_parse(comp, &a) == 0 && n < 16)
			chain[n++] = a;
	}
	if (n == 0) {
		sb_str(b, "  PCIe path: not readable\n");
		return;
	}
	sb_printf(b, "  PCIe path: %s\n", n == 1 ? "the GPU sits on the root complex" :
		  n == 2 ? "root port, then the GPU" : "root port, one or more bridges or switch ports, then the GPU");
	for (unsigned int i = 0; i < n; i++) {
		char d[GS_PATH_MAX], v[32] = "?", dv[32] = "?", spd[48] = "", wd[16] = "", mspd[48] = "", mwd[16] = "", name[256];

		gs_pathf(d, sizeof(d), "%s/bus/pci/devices/%s", sys, chain[i].str);
		gs_pathf(link, sizeof(link), "%s/vendor", d);
		gs_read_attr(link, v, sizeof(v));
		gs_pathf(link, sizeof(link), "%s/device", d);
		gs_read_attr(link, dv, sizeof(dv));
		gs_pathf(link, sizeof(link), "%s/current_link_speed", d);
		gs_read_attr(link, spd, sizeof(spd));
		gs_pathf(link, sizeof(link), "%s/current_link_width", d);
		gs_read_attr(link, wd, sizeof(wd));
		gs_pathf(link, sizeof(link), "%s/max_link_speed", d);
		gs_read_attr(link, mspd, sizeof(mspd));
		gs_pathf(link, sizeof(link), "%s/max_link_width", d);
		gs_read_attr(link, mwd, sizeof(mwd));
		name[0] = '\0';
		if (live)
			lspci_name(chain[i].str, name, sizeof(name));
		sb_printf(b, "    %s %s [%s:%s]%s%s", i == 0 && n > 1 ? "root port" : i == n - 1 ? "GPU" : "bridge   ", chain[i].str,
			  v + (strncmp(v, "0x", 2) == 0 ? 2 : 0), dv + (strncmp(dv, "0x", 2) == 0 ? 2 : 0), name[0] ? " " : "", name);
		if (spd[0] && wd[0])
			sb_printf(b, "; link %s x%s%s%s%s%s", spd, wd, mspd[0] ? " (max " : "", mspd, mspd[0] ? " x" : "", mwd);
		if (mspd[0] && mwd[0])
			sb_str(b, ")");
		sb_str(b, "\n");
	}
	/* The host bridge of the same domain: the chipset or CPU side of the path. */
	{
		char d[GS_PATH_MAX], v[32], dv[32], name[256], bdf[GS_BDF_STR_SIZE];

		snprintf(bdf, sizeof(bdf), "%04x:00:00.0", pf->domain);
		gs_pathf(d, sizeof(d), "%s/bus/pci/devices/%s", sys, bdf);
		gs_pathf(link, sizeof(link), "%s/vendor", d);
		if (gs_read_attr(link, v, sizeof(v)) == 0) {
			gs_pathf(link, sizeof(link), "%s/device", d);
			gs_read_attr(link, dv, sizeof(dv));
			name[0] = '\0';
			if (live)
				lspci_name(bdf, name, sizeof(name));
			sb_printf(b, "    host bridge %s [%s:%s]%s%s\n", bdf, v + 2, dv + 2, name[0] ? " " : "", name);
		}
	}
}

/* ---- capture of the package's own output -------------------------------- */

struct capture_job {
	int (*fn)(const struct capture_job *);
	const struct gs_diag_opts *opts;
};

static int job_status(const struct capture_job *j)
{
	return gs_cmd_status(j->opts);
}

static int job_hostcheck(const struct capture_job *j)
{
	return gs_hostcheck(j->opts, GS_HOSTCHECK_PRE);
}

/* Runs j with standard output and error in a temporary file; returns what it printed. */
static char *capture(const struct capture_job *j, int *rc)
{
	FILE *tmp = tmpfile();
	int so, se;
	off_t size;
	char *out;
	ssize_t got;

	*rc = -1;
	if (!tmp)
		return strdup("(output could not be captured: no temporary file)\n");
	fflush(NULL);
	so = dup(1);
	se = dup(2);
	if (so < 0 || se < 0) {
		fclose(tmp);
		return strdup("(output could not be captured)\n");
	}
	dup2(fileno(tmp), 1);
	dup2(fileno(tmp), 2);
	*rc = j->fn(j);
	fflush(NULL);
	dup2(so, 1);
	dup2(se, 2);
	close(so);
	close(se);
	size = lseek(fileno(tmp), 0, SEEK_END);
	lseek(fileno(tmp), 0, SEEK_SET);
	if (size < 0 || !(out = malloc((size_t)size + 1))) {
		fclose(tmp);
		return strdup("(output could not be captured)\n");
	}
	got = read(fileno(tmp), out, (size_t)size);
	out[got < 0 ? 0 : got] = '\0';
	fclose(tmp);
	return out;
}

/* ---- the report --------------------------------------------------------- */

#define LOG_MAX_LINES 120
#define JOURNAL_MAX (16u << 20)

/* The lines of cfg's canonical text that the defaults do not have. */
static void put_changed(struct sbuf *b, const struct gs_config *cfg)
{
	struct gs_config def;
	char a[4096], d[4096], *line, *save = NULL;
	int any = 0;

	gs_config_defaults(&def);
	if (gs_config_render(cfg, a, sizeof(a)) < 0 || gs_config_render(&def, d, sizeof(d)) < 0) {
		sb_str(b, "settings changed from the defaults: not readable\n");
		return;
	}
	for (line = strtok_r(a, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		char pat[4200];

		if (line[0] == '#' || !line[0])
			continue;
		snprintf(pat, sizeof(pat), "\n%s\n", line);
		{
			char dd[4200];

			snprintf(dd, sizeof(dd), "\n%s", d);
			if (strstr(dd, pat))
				continue;
		}
		if (!any)
			sb_str(b, "settings changed from the defaults (config");
		sb_printf(b, "%s %s", any ? "," : ":", line);
		any = 1;
	}
	if (any)
		sb_str(b, ")\n");
	else
		sb_printf(b, "settings changed from the defaults: none%s\n", cfg->present ? "" : " (no config file)");
}

static void put_gpus(struct sbuf *b, const char *sys, const struct gs_config *cfg, int live, const char *smi)
{
	struct gs_unselected u[GS_UNSELECTED_MAX];
	unsigned int n = gs_unselected_scan(sys, NULL, 0, u, GS_UNSELECTED_MAX), boot = 0;
	int above = -1;

	sb_printf(b, "NVIDIA GPUs found: %u\n", n);
	for (unsigned int i = 0; i < n; i++) {
		struct gs_card c;
		char d[GS_PATH_MAX], name[256], vram[160] = "";

		gs_card_inspect(sys, &u[i].pf, &c);
		gs_pathf(d, sizeof(d), "%s/bus/pci/devices/%s", sys, u[i].pf.str);
		sb_printf(b, "\nGPU %s\n", u[i].pf.str);
		sb_printf(b, "  PCI ID: %04x:%04x, subsystem %04x:%04x\n", c.vendor, c.device, c.subvendor, c.subdevice);
		sb_printf(b, "  model in the device table: %s\n", c.entry ? c.entry->name : "not listed");
		sb_printf(b, "  generation: %s\n", c.entry ? gs_generation_name(c.entry->generation) : "not in the device table");
		name[0] = '\0';
		if (live)
			lspci_name(u[i].pf.str, name, sizeof(name));
		if (name[0])
			sb_printf(b, "  lspci: %s\n", name);
		if (smi) {
			const char *p = smi;
			char key[32];

			snprintf(key, sizeof(key), "%02x:%02x.%u", c.pf.bus, c.pf.slot, c.pf.func);
			while (*p) {
				const char *nl = strchr(p, '\n');
				size_t ln = nl ? (size_t)(nl - p) : strlen(p);

				if (ci_find(p, ln, key)) {
					const char *comma = memchr(p, ',', ln);

					snprintf(vram, sizeof(vram), "%.*s", comma ? (int)(ln - (size_t)(comma - p) - 1) : (int)ln,
						 comma ? comma + 2 : p);
					break;
				}
				p += ln + (nl ? 1 : 0);
			}
		}
		sb_printf(b, "  VRAM and name (nvidia-smi): %s\n", vram[0] ? vram :
			  smi ? "this GPU is not listed" : "not available (nvidia-smi is not installed or NVIDIA's driver is not loaded)");
		sb_printf(b, "  boot display: %s\n", c.boot_vga == 1 ? "yes" : c.boot_vga == 0 ? "no" : "unknown");
		if (c.boot_vga == 1)
			boot++;
		sb_printf(b, "  driver: %s\n", c.driver[0] ? c.driver : "none");
		sb_printf(b, "  selected by geforce-sriov: %s\n", gs_addr_listed(cfg->bdfs, cfg->nbdfs, u[i].pf.str) ? "yes" : "no");
		sb_printf(b, "  SR-IOV: %s", c.has_sriov ? "presented" : "not presented");
		if (c.has_sriov)
			sb_printf(b, ", sriov_totalvfs=%u, VFs enabled=%u", c.totalvfs, c.numvfs);
		sb_str(b, "\n");
		sb_printf(b, "  ARI: ari_enabled=%d, root port ARI forwarding supported=%d\n", c.ari_enabled, c.bridge_ari_fwd_supported);
		sb_printf(b, "  IOMMU group: %s\n", c.iommu_group[0] ? c.iommu_group : "none");
		put_bars(b, d, &above);
		put_path(b, sys, &u[i].pf, live);
	}
	sb_printf(b, "\nboot display GPUs: %u of %u\n", boot, n);
	sb_printf(b, "Above 4G decoding (from where the BARs sit): %s\n", above > 0 ? "on, a BAR sits above 4 GiB" :
		  n ? "no BAR above 4 GiB seen (off, or the card has none)" : "not known");
}


/* The lines of text in the opposite order; malloc'd. */
static char *reverse_lines(const char *text)
{
	size_t len = strlen(text);
	char *out = malloc(len + 2), *w = out;
	const char *end = text + len;

	if (!out)
		return NULL;
	while (end > text) {
		const char *start = end;

		if (start[-1] == '\n')
			start--;
		while (start > text && start[-1] != '\n')
			start--;
		memcpy(w, start, (size_t)(end - start));
		w += end - start;
		if (w[-1] != '\n')
			*w++ = '\n';
		end = start;
	}
	*w = '\0';
	return out;
}

/*
 * The kernel log of this boot through journalctl, newest line first so that a long log keeps its newest
 * part, else through dmesg; only the geforce_sriov, NVRM and AER lines are kept.
 */
static void put_log(struct sbuf *b)
{
	char *log = malloc(JOURNAL_MAX), *ordered, *lines;
	const char *journal[] = { "journalctl", "-k", "-b", "--no-pager", "--no-hostname", "-r", NULL };
	const char *dmesg[] = { "dmesg", NULL };
	unsigned int omitted;
	int rc, newest_first = 1;

	if (!log) {
		sb_str(b, "kernel log: not read (out of memory)\n");
		return;
	}
	rc = gs_run_capture(journal, log, JOURNAL_MAX);
	if (rc != 0 || !log[0]) {
		int jrc = rc;

		newest_first = 0;
		rc = gs_run_capture(dmesg, log, JOURNAL_MAX);
		if (rc != 0 || !log[0]) {
			sb_printf(b, "kernel log: not readable (%s). Run the command with sudo, or read it with `journalctl -k -b --no-hostname`\n",
				  jrc == -1 && rc == -1 ? "journalctl and dmesg did not answer in time or are missing" :
				  "journalctl and dmesg refused or are missing");
			free(log);
			return;
		}
	}
	ordered = newest_first ? reverse_lines(log) : strdup(log);
	free(log);
	if (!ordered) {
		sb_str(b, "kernel log: not read (out of memory)\n");
		return;
	}
	lines = gs_report_log_filter(ordered, LOG_MAX_LINES, &omitted);
	free(ordered);
	if (omitted)
		sb_printf(b, "(%u earlier matching lines left out)\n", omitted);
	sb_str(b, lines[0] ? lines : "(no matching lines this boot)\n");
	free(lines);
}

/* The VRAM lines nvidia-smi gives: "bus id, name, memory"; NULL when the program is not there. */
static char *smi_lines(void)
{
	const char *argv[] = { "nvidia-smi", "--query-gpu=pci.bus_id,name,memory.total", "--format=csv,noheader", NULL };
	char *buf = malloc(64 * 1024);

	if (!buf || gs_run_capture(argv, buf, 64 * 1024) != 0 || !buf[0]) {
		free(buf);
		return NULL;
	}
	return buf;
}

static void put_driver(struct sbuf *b, const char *sys, int live)
{
	char ver[64] = "", line[256];
	struct gs_build bi;
	struct gs_module_state m;
	int have = gs_build_identity(NULL, live, &bi);

	if (!live) {
		sb_str(b, "NVIDIA host driver: not collected (diagnostic root)\n");
		return;
	}
	gs_nvidia_version(GS_LIVE_PROC, ver, sizeof(ver));
	if (ver[0]) {
		gs_version_format(gs_version_confirmed(GS_VERSION_HOST, ver) ? GS_VERSION_MSG_CONFIRMED : GS_VERSION_MSG_STATUS,
				  ver, line, sizeof(line));
		sb_printf(b, "NVIDIA host driver loaded: %s\n", line);
	} else {
		sb_str(b, "NVIDIA host driver loaded: no\n");
	}
	if (have && bi.driver_version[0])
		sb_printf(b, "NVIDIA host driver of the installed build: %s\n", bi.driver_version);
	if (have && bi.state == GS_BUILD_MATCHES && !gs_loaded_not_installed(sys, NULL))
		sb_str(b, "patched nvidia.ko in use: yes (the loaded module is the build geforce-sriov installed)\n");
	else if (have && bi.state == GS_BUILD_MATCHES)
		sb_str(b, "patched nvidia.ko in use: no (the loaded module is not the installed build)\n");
	else if (have && bi.state == GS_BUILD_PRESENT)
		sb_str(b, "patched nvidia.ko in use: no (the installed nvidia.ko is not the build geforce-sriov recorded)\n");
	else
		sb_str(b, "patched nvidia.ko in use: no (no build record for this kernel)\n");
	gs_read_module_state(sys, &m);
	sb_printf(b, "geforce_sriov module: %s", m.loaded ? "loaded" : "not loaded");
	if (m.loaded)
		sb_printf(b, " (ari=%s msix=%s vfs=%s)", m.ari, m.msix, m.vfs[0] ? m.vfs : "none");
	sb_str(b, "\n");
}

/* How many running processes name one of the VFs on their command line: a VM that was given a VF. */
static unsigned int vms_using(const char *proc, const struct gs_addr *vfs, unsigned int nvf)
{
	DIR *d = opendir(proc);
	struct dirent *de;
	unsigned int n = 0;

	if (!d)
		return 0;
	while ((de = readdir(d))) {
		char p[GS_PATH_MAX], *data;
		size_t len;
		int hit = 0;

		if (!isdigit((unsigned char)de->d_name[0]) || gs_pathf(p, sizeof(p), "%s/%s/cmdline", proc, de->d_name) ||
		    gs_read_whole(p, &data, &len, 1 << 18))
			continue;
		for (unsigned int i = 0; i < nvf && !hit; i++)
			hit = memmem(data, len, vfs[i].str, strlen(vfs[i].str)) != NULL;
		free(data);
		n += hit;
	}
	closedir(d);
	return n;
}

/*
 * The state line near the top of the block: how far this host is. A report taken right after the install shows "not yet
 * activated", which is fine to keep for later; the most useful one comes after the power cycle and a first VM.
 */
static void put_state(struct sbuf *b, const char *sys, const struct gs_config *cfg, int live)
{
	unsigned int total = 0, vms = 0, cards = 0;
	const char *tail = "";

	if (live) {
		if (gs_exists(GS_ATTEMPT_MARKER))
			tail = " (the activation lock is set)";
		else if (gs_loaded_not_installed(sys, NULL))
			tail = " (a power cycle is pending: the running nvidia module is not the installed build)";
	}
	char where[512] = "";

	if (!cfg->present) {
		sb_str(b, "State: not installed (no config file), VFs: 0, VMs using a VF now: none\n");
		return;
	}
	for (unsigned int i = 0; i < cfg->nbdfs; i++) {
		struct gs_card c;

		gs_card_inspect(sys, &cfg->bdfs[i], &c);
		if (!c.present || !c.numvfs)
			continue;
		total += c.numvfs;
		cards++;
		if (strlen(where) + 24 < sizeof(where))
			snprintf(where + strlen(where), sizeof(where) - strlen(where), "%s%u on %s", where[0] ? ", " : "", c.numvfs,
				 cfg->bdfs[i].str);
		if (live && c.numvfs <= GS_VFS_MAX) {
			struct gs_addr vfs[GS_VFS_MAX];
			char why[128];

			if (gs_vf_list(sys, &c.pf, c.numvfs, vfs, why, sizeof(why)) == 0)
				vms += vms_using(GS_LIVE_PROC, vfs, c.numvfs);
		}
	}
	if (!total) {
		sb_printf(b, "State: installed, not yet activated%s, VFs: 0, VMs using a VF now: none\n",
			  tail[0] ? tail : " (a power cycle may be pending)");
		return;
	}
	sb_printf(b, "State: active%s, VFs: %s", tail, where);
	if (!live)
		sb_str(b, ", VMs using a VF now: not checked (diagnostic root)\n");
	else
		sb_printf(b, ", VMs using a VF now: %u (a VM that ran earlier is not visible to the host)\n", vms);
	(void)cards;
}

/* The body of the report, before redaction. The caller frees it. */
char *gs_report_body(const struct gs_report_opts *o)
{
	struct sbuf b = { 0 };
	const char *sys = o->sysroot ? o->sysroot : GS_LIVE_SYSFS;
	int live = gs_is_live_root(sys), rc_status = 0, rc_check = 0;
	struct gs_diag_opts dopts;
	struct gs_config cfg;
	char err[512], v[256], *smi = NULL, *text;
	const char *cfg_path = NULL;
	struct capture_job job;

	memset(&dopts, 0, sizeof(dopts));
	dopts.sysroot = o->sysroot;
	dopts.config_path = o->config_path;
	sb_put(&b, "", 0);
	if (gs_diag_config(&dopts, &cfg, &cfg_path, err, sizeof(err))) {
		gs_config_defaults(&cfg);
		sb_printf(&b, "config: %s\n", err);
	}

	put_state(&b, sys, &cfg, live);
	sb_str(&b, "\n== Host ==\n");
	sb_printf(&b, "geforce-sriov: %s\n", GS_VERSION);
	if (live) {
		struct utsname u;
		char p[GS_PATH_MAX], cpu[128] = "";
		char *ci;
		size_t cl;

		if (os_release_value("PRETTY_NAME", v, sizeof(v)) || os_release_value("NAME", v, sizeof(v)))
			sb_printf(&b, "host OS: %s\n", v);
		else
			sb_str(&b, "host OS: not readable\n");
		if (uname(&u) == 0)
			sb_printf(&b, "kernel: %s (%s)\n", u.release, u.machine);
		put_hypervisors(&b);
		if (!gs_pathf(p, sizeof(p), "%s/cpuinfo", GS_LIVE_PROC) && !gs_read_whole(p, &ci, &cl, 1 << 20)) {
			const char *m = strstr(ci, "model name");

			if (m && (m = strchr(m, ':'))) {
				size_t k = strcspn(m + 2, "\n");

				snprintf(cpu, sizeof(cpu), "%.*s", (int)k, m + 2);
			}
			sb_printf(&b, "CPU: %s%s\n", cpu[0] ? cpu : "not readable",
				  strstr(ci, " hypervisor") ? " (this host runs inside a virtual machine)" : "");
			free(ci);
		}
		put_dmi(&b, sys);
		put_cmdline(&b, GS_LIVE_PROC);
		{
			char dir[GS_PATH_MAX];
			unsigned int groups;

			gs_pathf(dir, sizeof(dir), "%s/kernel/iommu_groups", sys);
			groups = count_dir(dir);
			sb_printf(&b, "IOMMU: %s\n", groups ? "active" : "no IOMMU groups (the IOMMU is off or not supported)");
			if (groups)
				sb_printf(&b, "IOMMU groups: %u\n", groups);
		}
	} else {
		sb_str(&b, "host OS, kernel, hypervisor, board and command line: not collected (diagnostic root)\n");
	}

	sb_str(&b, "\n== GPUs ==\n");
	if (live)
		smi = smi_lines();
	put_gpus(&b, sys, &cfg, live, smi);
	free(smi);

	sb_str(&b, "\n== Software and settings ==\n");
	put_driver(&b, sys, live);
	put_changed(&b, &cfg);
	sb_printf(&b, "VFs per card: %u%s\n", gs_config_vfs(&cfg), cfg.vfs ? " (set in the config)" : " (default)");

	sb_str(&b, "\n== geforce-sriov status ==\n");
	job.fn = job_status;
	job.opts = &dopts;
	text = capture(&job, &rc_status);
	sb_str(&b, text);
	sb_printf(&b, "(exit status %d)\n", rc_status);
	free(text);

	sb_str(&b, "\n== geforce-sriov install --dry-run (the host checks) ==\n");
	job.fn = job_hostcheck;
	text = capture(&job, &rc_check);
	sb_str(&b, text);
	sb_printf(&b, "(exit status %d)\n", rc_check);
	free(text);

	sb_str(&b, "\n== Kernel log (geforce_sriov, NVRM and AER lines of this boot) ==\n");
	if (live)
		put_log(&b);
	else
		sb_str(&b, "not collected (diagnostic root)\n");
	return b.p;
}

static const char *const report_removed_fmt =
	"Removed before this report was written: IP addresses (%u), MAC addresses (%u), serial numbers (%u),\n"
	"GPU UUIDs (%u), host and user names (%u) and licence lines (%u).\n";

int gs_cmd_report(const struct gs_report_opts *o)
{
	struct gs_redactor r;
	struct sbuf out = { 0 };
	char *body, *clean;


	if (!o->sysroot && geteuid() != 0)
		fprintf(stderr, "geforce-sriov: not running as root: the kernel log and some checks may be missing. "
			"Run `sudo geforce-sriov report` for the full report.\n");
	body = gs_report_body(o);
	gs_redactor_init(&r);
	gs_redactor_collect(&r);
	clean = gs_redact(&r, body);
	free(body);

	sb_str(&out, "~~~text\n");
	sb_printf(&out, "geforce-sriov compatibility report (geforce-sriov %s)\n", GS_VERSION);
	sb_printf(&out, report_removed_fmt, r.n_ip, r.n_mac, r.n_serial, r.n_uuid, r.n_name, r.n_licence);
	sb_str(&out, "Not included: anything from inside the guests. The issue form asks for those.\n\n");
	/* A line that starts with a fence would end the block early. */
	for (const char *s = clean; *s;) {
		const char *nl = strchr(s, '\n');
		size_t n = nl ? (size_t)(nl - s) : strlen(s);

		if (n >= 3 && strncmp(s, "~~~", 3) == 0)
			sb_put(&out, " ", 1);
		sb_put(&out, s, n);
		sb_put(&out, "\n", 1);
		s += n + (nl ? 1 : 0);
	}
	sb_str(&out, "~~~\n");
	free(clean);

	if (o->out_path) {
		if (gs_write_file_atomic(o->out_path, out.p, out.len, 0644)) {
			fprintf(stderr, "geforce-sriov: cannot write %s\n", o->out_path);
			free(out.p);
			return GS_EXIT_FAIL;
		}
		printf("Report written to %s. Paste its whole contents into the compatibility report form.\n", o->out_path);
	} else {
		fwrite(out.p, 1, out.len, stdout);
		if (isatty(1))
			fprintf(stderr, "\nCopy everything from the first ~~~text line to the last ~~~ line into the compatibility report form.\n");
	}
	free(out.p);
	return GS_EXIT_OK;
}
