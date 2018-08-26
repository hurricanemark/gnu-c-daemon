// NOTE: In order to keep the size / verbosity of code examples to a minimum, library function
// calls will generally not include error checking and handling. Example:
//
//     p = malloc(...);                if ((p = malloc(...)) == NULL)
//                                     {
//                                       ... handle error ...
//                                     }
//
// However, any necessary, application-specific error-related code, will still be used. Code
// examples will endeavour, wherever possible, to make use of:
//
// * C99 Features e.g. variable-length arrays, non-const aggregate initialisers
// * GNU Extensions e.g. nested functions, statement expressions
//
// The aim of doing so is to reduce redundancy [i.e. copious examples of older / standard C
// already exist] as well as enhance the information value of each PLEAC example.
//
// Another item worthy of note is the use of writeable 'static local storage' in many custom
// functions. Whilst a commonly-used technique that makes functions self-contained, and easier
// to use [which is precisely why it is used here], it is not viable in multi-threaded code;
// examples need to be suitably modified to work in such code. The section, 'Printing a Date',
// in Chapter 3: Dates and Times, discusses this issue, and provides illustrative examples.
//
// The GNU C Library provides extensive, if somewhat low-level, date / time functionality. The
// relevant section of the manual may be found at:
//
//     http://www.gnu.org/software/libc/manual/html_mono/libc.html#Date%20and%20Time
//
// Outline of some of the more important concepts:
//
// * Calendar time represented in three forms:
//   - Simple time [a.k.a. Epoch Seconds, seconds since Jan 1, 1970]; represented by the
//    'time_t' type [generally implemented as a 32 bit integer]
//   - Broken-down time; represented by 'struct tm', having a field for each time component
//   - Formatted string; certain string formats are printable and parseable as valid calendar
//     times
//
// * Date manipulations are ordinarily performed using broken-down time form, and are converted
//   to / from this form as the need arises:
//   - Input
//     + simple -> broken-down: 'localtime' / 'gmtime'
//     + string -> broken-down: 'strptime' / 'getdate'
//   - Arithmetic
//     + broken-down -> simple: 'mktime'
//   - Output
//     + broken-down -> string: 'strftime', 'asctime'
//   
//   The above list shows that a date / time value might be either be read in as a string [then
//   parsed, and converted], or converted from a simple-time value [e.g. the 'time' and
//   'gettimeofday' routines return the current date / time as a simple-time value]. Date
//   arithmetic can, of course, be performed using the component fields of a broken-time value,
//   but would, more commonly, be first converted to a simple-time value [via 'mktime'], the
//   relevant operations performed, and converted back. Date / time output is ordinarily in
//   string form, the conversion most likely performed using 'strftime' routine, but use of the
//   'printf' family is also possible
//
// * Despite a few exceptions, the date / time library routines are well standardised [just
//   include the <time.h> header], so are available across platforms. The widely-implemented,
//   though *NIX-specific, routines include:
//   - 'gettimeofday', essentially a higher resolution [microseconds, possibly nanoseconds]
//      version of 'time'
//   - 'strptime' and 'getdate', both routines similar in functionlity to 'sscanf' but using
//     format specifications specialised for date / time handling
//
// Implementations of general purpose date routines [which are generally used in several
// sections] appear here. Protoypes appear in each section in which they are used. To
// successfully compile examples ensure the relevant code from this section is copied into
// the example source file.
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>
#include <math.h>

struct tm mk_tm(int year, int month, int day, int hour, int minute, int second)
{
  struct tm tmv =
  {
    .tm_hour = hour, .tm_min = minute, .tm_sec = second,
    .tm_year = year - 1900, .tm_mon = month - 1, .tm_mday = day,
    .tm_isdst = -1
  };

  mktime(&tmv);

  return tmv;
}

struct tm mk_tm_unfilled(void)
{
  // -1 value used to indicate 'unfilled' since zero is a legitimate value in some fields
  return ((struct tm) { -1, -1, -1, -1, -1, -1, -1, -1, -1 });
}

struct tm mk_tm_zero(void)
{
  return ((struct tm) { 0, 0, 0, 0, 0, 0, -1, -1, -1 });
}

void show_tm(const struct tm* tmvptr)
{
  int year = tmvptr->tm_year > -1 ? tmvptr->tm_year + 1900 : tmvptr->tm_year;
  int month = tmvptr->tm_mon > -1 ? tmvptr->tm_mon + 1 : tmvptr->tm_mon;

  printf("Y/M/D H:M:S -> %04d/%02d/%02d %02d:%02d:%02d\n",
    year, month, tmvptr->tm_mday,
    tmvptr->tm_hour, tmvptr->tm_min, tmvptr->tm_sec);

  printf("DOW: %02d\nDOY: %02d\nDaylight Saving: %02d\n",
    tmvptr->tm_wday, tmvptr->tm_yday, tmvptr->tm_isdst);

  fflush(stdout);
}

// Note: Equivalent of 'timegm' function implemented on *NIX platforms [code may be 'unpacked'
// for compilers not supporting nested functions] using the more portable technique of changing,
// temporarily, the TZ value
time_t mktime_utc(struct tm* tmvptr)
{
  const char NUL = '\0'; char tzold[32] = {NUL}, tznew[32] = {NUL};

  void save_tz(void)
  {
    char* tz = getenv("TZ"); if (tz != NULL) strcpy(tzold, tz);
  }

  void restore_tz(void)
  {
    char* tz = (tzold[0] != NUL) ? strcat(strcpy(tznew, "TZ="), tzold) : "TZ";
    putenv(tz);
  }

  save_tz();
  putenv("TZ=UTC");
  time_t utc = mktime(tmvptr);
  restore_tz();

  return utc;
}

// ----

// The following helper functions are loosely based on the implementations found in the
// corresponding section(s) of PLEAC-PHP. The 'mk_date_interval' function is notable for
// several reasons:
// * Heavy use of pointer manipulation to search and tokenise string contents; illustrative
//   of a faster, more lightweight, though considerably more complex, approach to this task
//   when compared with use of library functions like 'strtok', 'strstr' and 'strchr'
// * Comprehensive example of both variable-argument handling, and of sensible nested function
//   use
// * The 'parse_entry' nested function illustrates an approach that can be used for mimicing
//   named function parameters
// * Use of a delimited string as a lookup table in the 'getvalue' nested function is mainly
//   illustrative. Better performance can be obtained by other means; if still opting for a
//   string-based lookup table approach, a 'perfect hash'-based technique would be ideal,
//   though would require much more code to implement 
//
// This function, together with 'to_epoch' and 'from_epoch', make use of string parameters
// to represent a keyword. In C this approach wouldn't ordinarily be used because such
// information can most often be encode in integer form e.g. integer constants or enumerations,
// and the processing of integers is dramatically faster and far more efficient than string
// operations such as linear searching and comparision. However, the reason for adopting this
// string-based approach is to mimic the beahviour of the PLEAC-PHP implementations, as well
// as illustrate various C techniques such as pointer manipulation and variable argument
// handling.
// 
// As an aside, error checking is minimal in most of these functions, and could certainly be
// improved.

time_t mk_date_interval(const char* arg1, ...)
{
  static const char EQ = '=', COMMA = ',', NUL = '\0';
  static char buffer[16]; 

  // ----

  char* parse_entry(const char* entry, int* value)
  {
    char* p = (char*) entry; // Assumes: "key=value" form

    // Extract, and convert 'value'
    while (*p++ != EQ) if (*p == NUL) return NULL; 
    *value = atoi(p);

    // Extract 'key', copy to buffer for return
    p = buffer;
    while (*entry != EQ) *p++ = *entry++;
    *p = NUL;

    return buffer;
  }

  // ----

  int getvalue(const char* key)
  {
    // Lookup table implemented as a delimited string
    static const char* const TBL = "sec=1,min=60,hou=3600,day=86400,wee=604800";

    // Perform table lookup [via linear search (slow) of string]
    char* p = (char*) strcasestr(TBL, key);
    if (!p) return 0;

    // Extract table value. Since table is in delimited string form, use pointer
    // manipulation to mark start and end locations of required substring [value for key].
    // Since locations are in a string constant, NUL-termination cannot be performed
    // in-place, so substring is copied to a buffer for subsequent processing
    while (*p++ != EQ) ; 
    char* q = p;
    while (*q != NUL) if (*q == COMMA) break; else ++q; 
    memcpy(buffer, p, q - p);
    *(buffer + (q - p)) = NUL;

    return atoi(buffer);
  }

  // ----

  int interval = 0, value; const char* key;

  // Extract values from 1st argument
  if (!(key = parse_entry(arg1, &value))) return 0;
  interval += value * getvalue(key);

  // Setup for variable argument handling, and extract values from each of these
  const char* arg; va_list ap;

  va_start(ap, arg1);

  while ((arg = va_arg(ap, const char*)) != NULL)
  {
    if (!(key = parse_entry(arg, &value))) return 0;
    interval += value * getvalue(key);
  }

  va_end(ap);

  return interval;
}  

double get_date_interval_value(const char* intvltype)
{
  double interval = 0.0;

  // What, no lookup table ;) ?
  switch (*intvltype)
  {
    case 'd' : interval = strncasecmp(intvltype, "day", 3) == 0 ? 86400.0 : 0.0; break;
    case 'h' : interval = strncasecmp(intvltype, "hou", 3) == 0 ? 3600.0 : 0.0; break;
    case 'm' : interval = strncasecmp(intvltype, "min", 3) == 0 ? 60.0 : 0.0; break;
    case 's' : interval = strncasecmp(intvltype, "sec", 3) == 0 ? 1.0 : 0.0; break;
    case 'w' : interval = strncasecmp(intvltype, "wee", 3) == 0 ? 604800.0 : 0.0; break;
  }

  return interval;
}

time_t to_epoch(const char* intvltype, double multiple)
{
  return (time_t) floor(multiple * get_date_interval_value(intvltype));
}

double from_epoch(const char* intvltype, time_t tv)
{
  double interval = get_date_interval_value(intvltype);
  return (interval > 0.0) ? tv / interval : 0.0;
}

// ----

int is_parseable_date(const char* date, const char* fmt, struct tm* tmvptr)
{
  static char datebuf[128];

  // Date / time string is parsed according to format specification; if it fails it can
  // be assumed a format or type error occurred
  if (strptime(date, fmt, tmvptr) != 0)
  {
    datebuf[0] = '\1';
    // Attempt to generate a date / time string using the previously created broken-time
    // value; if it succeeds it can be assumed the broken-down value is sound, but further
    // validation is needed to ensure the value is truly 'valid'
    if ( !(strftime(datebuf, sizeof(datebuf), fmt, tmvptr) == 0 && datebuf[0] != '\0') )
       return 1; //true;
  }

  return 0; //false;   
}

int is_leap_year(int year)
{
  return ( ((year % 4) == 0) && ((year % 100) != 0) || ((year % 400) == 0) );
}

int doy(int year, int month, int day)
{
  const int BASE = -1; // Zero base [i.e. 1st day is zero] assumed
  static const int cumdays[] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 };

  if (month < 1 || month > 12) return -1;
  return BASE + cumdays[month - 1] + day + (is_leap_year(year) && month > 2 ? 1 : 0);
}

const char* dayname(int day)
{
  static const char* dnams[] = { "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday" };
  if (day < 0 || day > 6) return NULL;
  return dnams[day];
}

// ----


int is_valid_hms(int hour, int minute, int second)
{
  // Purely arbitrary choice; allows 24:00:00, but may be omitted
  if (hour == 24 && minute == 0 && second == 0)
    return 1; //true;

  if (hour > -1 && hour < 24)
    if (minute > -1 && minute < 60)
      if (second > -1 && second < 60)
        return 1; //true;

  return 0; //false;
}

int is_valid_ymd(int year, int month, int day)
{
  static const int mtbl[] = { -1, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

  // Purely arbitrary choice; may be modified or omitted
  if (year < 1970 || year > 2038) return 0; //false;

   if (month > 0 && month < 13 && day > 0 && day <= mtbl[month]) return 1; //true;
  if (day == 29 && month == 2 && is_leap_year(year)) return 1; //true;

  return 0;  //false;
}

int is_valid_tm(struct tm* tmvptr)
{
  return
    is_valid_hms(tmvptr->tm_hour, tmvptr->tm_min, tmvptr->tm_sec) &&
    is_valid_ymd(tmvptr->tm_year + 1900, tmvptr->tm_mon + 1, tmvptr->tm_mday) &&
    mktime(tmvptr) != -1;
}


// ----

const char* mk_fmt_date(const char* fmt, const struct tm* tmvptr)
{
  static char datebuf[64];
  return (strftime(datebuf, sizeof(datebuf), fmt, tmvptr) == 0) ? NULL : datebuf;
}

// ----
double hms_to_frac(int hour, int min, int sec)
{
  return (hour * 3600 + min * 60 + sec) / 86400.;
}

void frac_to_hms(double frac, int* hour, int* min, int* sec)
{
  int seconds = floor(frac * 86400.);

  *hour = seconds / 3600;
  *min = (seconds - *hour * 3600) / 60;
  *sec = (seconds - (*hour * 3600 + *min * 60));
}
