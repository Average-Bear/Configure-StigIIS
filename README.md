# Configure-StigIIS    

Author: JBear
    Date: 9/5/2018

    STIG Release: 2018 Q3
    Not all IIS STIG items are addressed, as some require specific environment information. 
    This will either configure or report the status of the vulnerabilities below and eliminate a major portion of all items needing to be reviewed.
    
    Before proceeding, snapshot any virtual machine you run this on. If you notice that your sites go down, revert the snapshot and comment out sections of the functions at the end of this script. There are some functions built below that have had the configuration portion commented out purposesly because that settings broke a portion of the Web Server (SolarWinds specfically).
    Feel free to uncomment and test these for yourself, if needed. 

    Reports will be output to the $ServerPath variable; you will need to set this for the desired location.

    Configured/Reported Vulnerabilities: 
    V-76679, V-76779, V-76781, V-76681, V-76783, V-76683, V-76785, V-76685, V-76787, V-76687, V-76689, V-76789, V-76791, V-76695, V-76697, V-76795, V-76701, V-76703, V-76707, V-76719, V-76709, V-76711, V-76797, V-76713, V-76803, 
    V-76715, V-76717, V-76725, V-76727, V-76777, V-76731, V-76733, V-76829, V-76735, V-76737, V-76835, V-76753, V-76755, V-76757, V-76855, V-76759, V-76767, V-76769, V-76771, V-76773, V-76775, V-76813, V-76805, V-76809, V-76851, 
    V-76861, V-76811, V-76817, V-76819, V-76821, V-76823, V-76825, V-76827, V-76831, V-76837, V-76839, V-76841, V-76859, V-76867, V-76869, V-76871, V-76873, V-76875, V-76877, V-76879, V-76881, V-76883

    Require Manual Checks:
    V-76719, (V-76695, V-76697, V-76795), (V-76701, V-76751), V-76707, V-76745
