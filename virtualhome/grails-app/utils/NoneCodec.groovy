/*
 * HACK: Work around Grails 2.2.3's new default encoding of arguments to i18n messages.
 * See http://jira.grails.org/browse/GRAILS-10099
 *
 * Remove this when we target Grails 2.3
 * Referenced by views/templates/_passwordinput.gsp
 */
class NoneCodec {
  def encode = { it }
}
