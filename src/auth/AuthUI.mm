#import "AuthUI.h"
#import "Config.h"
#import "AuthManager.h"

// 面板窗口用静态强引用持有,显示期间不释放
@class AuthPanelViewController;
static UIWindow *_panelWindow = nil;
static id _keyWindowObserver = nil;
static __weak AuthPanelViewController *_activePanel = nil;

NSString * const AuthUIActivatedNotification = @"AuthDylibActivated";

// 面板可见期间,任何其他窗口成为 key(宿主内其他验证面板/弹层)→ 立即压回面板之下。
// 同级窗口按加入顺序叠放,hidden 开关强制重新入列置顶;用户正在输入时不打扰
// (实现放在 AuthPanelViewController 定义之后,见 HandleKeyWindowChange)

static UIColor *AuthUISecondaryColor(void) {
    if (@available(iOS 13.0, *)) return [UIColor secondaryLabelColor];
    return [UIColor grayColor];
}

static UIColor *AuthUIGreenColor(void) {
    if (@available(iOS 13.0, *)) return [UIColor systemGreenColor];
    return [UIColor colorWithRed:0.2 green:0.65 blue:0.25 alpha:1];
}

// 到期时间展示:v4.3 ISO 8601 UTC("2026-09-29T10:29:29Z")与旧格式("2026-09-29 10:29:29")
// 均按 UTC 解析后换算设备本地时区显示,任意时区设备看到的都是正确的本地到期时刻
static NSString *FormatExpiryLocal(NSString *raw) {
    if (![raw isKindOfClass:[NSString class]] || raw.length < 19) return @"";
    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
    fmt.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
    NSDate *date = nil;
    if ([raw containsString:@"T"]) {
        fmt.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss'Z'";
        date = [fmt dateFromString:raw];
    }
    if (!date) {
        fmt.dateFormat = @"yyyy-MM-dd HH:mm:ss";
        date = [fmt dateFromString:raw];
    }
    if (!date) return raw; // 未知格式原样透出
    NSDateFormatter *out = [[NSDateFormatter alloc] init];
    out.dateFormat = @"yyyy-MM-dd HH:mm";
    out.timeZone = [NSTimeZone systemTimeZone];
    return [out stringFromDate:date];
}

@interface AuthPanelViewController : UIViewController <UITextFieldDelegate>
@property (nonatomic, strong) UIView *card;
@property (nonatomic, strong) UITextField *cardField;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UIButton *verifyButton;
@property (nonatomic, strong) NSLayoutConstraint *cardCenterY;
@property (nonatomic, assign) CGFloat cardCenterYInitial;
@end

@implementation AuthPanelViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithWhite:0 alpha:0.55];

    _card = [[UIView alloc] init];
    if (@available(iOS 13.0, *)) _card.backgroundColor = [UIColor secondarySystemBackgroundColor];
    else _card.backgroundColor = [UIColor whiteColor];
    _card.layer.cornerRadius = 14;
    _card.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_card];

    UILabel *title = [[UILabel alloc] init];
    title.text = AUTH_APP_TITLE;
    title.textAlignment = NSTextAlignmentCenter;
    title.font = [UIFont boldSystemFontOfSize:17];
    if (@available(iOS 13.0, *)) title.textColor = [UIColor labelColor];
    else title.textColor = [UIColor blackColor];
    title.translatesAutoresizingMaskIntoConstraints = NO;

    _cardField = [[UITextField alloc] init];
    _cardField.borderStyle = UITextBorderStyleRoundedRect;
    _cardField.placeholder = @"请输入卡密";
    _cardField.keyboardType = UIKeyboardTypeASCIICapable;
    _cardField.autocorrectionType = UITextAutocorrectionTypeNo;
    _cardField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    _cardField.clearButtonMode = UITextFieldViewModeWhileEditing;
    _cardField.returnKeyType = UIReturnKeyDone;
    _cardField.delegate = self;
    _cardField.translatesAutoresizingMaskIntoConstraints = NO;

    _statusLabel = [[UILabel alloc] init];
    _statusLabel.text = @"输入卡密完成激活,绑定本机使用";
    _statusLabel.textAlignment = NSTextAlignmentCenter;
    _statusLabel.font = [UIFont systemFontOfSize:13];
    _statusLabel.numberOfLines = 2;
    _statusLabel.textColor = AuthUISecondaryColor();
    _statusLabel.translatesAutoresizingMaskIntoConstraints = NO;

    _verifyButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [_verifyButton setTitle:@"激 活" forState:UIControlStateNormal];
    _verifyButton.titleLabel.font = [UIFont boldSystemFontOfSize:16];
    [_verifyButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    if (@available(iOS 13.0, *)) _verifyButton.backgroundColor = [UIColor systemBlueColor];
    else _verifyButton.backgroundColor = [UIColor colorWithRed:0 green:0.48 blue:1 alpha:1];
    _verifyButton.layer.cornerRadius = 10;
    _verifyButton.translatesAutoresizingMaskIntoConstraints = NO;
    [_verifyButton addTarget:self action:@selector(verifyTapped) forControlEvents:UIControlEventTouchUpInside];

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[title, _cardField, _statusLabel, _verifyButton]];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 14;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [_card addSubview:stack];

    NSLayoutConstraint *centerY = [_card.centerYAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.centerYAnchor constant:-80];
    self.cardCenterY = centerY;

    [NSLayoutConstraint activateConstraints:@[
        [_card.centerXAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.centerXAnchor],
        centerY,
        [_card.widthAnchor constraintEqualToConstant:290],
        [stack.topAnchor constraintEqualToAnchor:_card.topAnchor constant:20],
        [stack.leadingAnchor constraintEqualToAnchor:_card.leadingAnchor constant:18],
        [stack.trailingAnchor constraintEqualToAnchor:_card.trailingAnchor constant:-18],
        [stack.bottomAnchor constraintEqualToAnchor:_card.bottomAnchor constant:-20],
        [_verifyButton.heightAnchor constraintEqualToConstant:42],
    ]];
    self.cardCenterYInitial = self.cardCenterY.constant;

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(keyboardWillChange:)
                                                 name:UIKeyboardWillChangeFrameNotification
                                               object:nil];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

#pragma mark - Keyboard

- (void)keyboardWillChange:(NSNotification *)note {
    CGRect end = [note.userInfo[UIKeyboardFrameEndUserInfoKey] CGRectValue];
    if (!self.view.window) return;
    CGFloat keyboardTop = end.origin.y;
    dispatch_async(dispatch_get_main_queue(), ^{
        [self.view layoutIfNeeded];
        CGRect cardFrame = [self.card convertRect:self.card.bounds toView:nil];
        CGFloat overlap = CGRectGetMaxY(cardFrame) + 12 - keyboardTop;
        [UIView animateWithDuration:0.25 animations:^{
            self.cardCenterY.constant = self.cardCenterYInitial - MAX(overlap, 0);
            [self.view layoutIfNeeded];
        }];
    });
}

#pragma mark - Actions

- (void)setStatus:(NSString *)text color:(UIColor *)color {
    self.statusLabel.text = text;
    self.statusLabel.textColor = color;
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    [self verifyTapped];
    return YES;
}

- (void)verifyTapped {
    if (self.verifyButton.enabled == NO) return;
    NSString *card = [self.cardField.text
        stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (card.length == 0) {
        [self setStatus:@"请输入卡密" color:[UIColor systemRedColor]];
        return;
    }

    self.verifyButton.enabled = NO;
    self.verifyButton.alpha = 0.5;
    [self setStatus:@"激活中…" color:AuthUISecondaryColor()];

    [[AuthManager shared] activateCard:card
        callback:^(AuthResult result, NSString *msg, NSDictionary *info) {
        if (result == AuthResultOK) {
            self.cardField.enabled = NO;
            self.verifyButton.enabled = NO;
            self.verifyButton.alpha = 0.5;
            // 到期时间按设备本地时区展示(服务端 v4.3 起为 UTC ISO 格式)
            NSString *date = FormatExpiryLocal(info[@"expires_at"]);
            NSString *done = date.length > 0
                ? [NSString stringWithFormat:@"激活成功,有效期至 %@", date]
                : @"激活成功";
            [self setStatus:done color:AuthUIGreenColor()];
            [[NSNotificationCenter defaultCenter]
                postNotificationName:AuthUIActivatedNotification object:nil];
            [AuthUI closePanelAfterDelay:2.5];
        } else {
            // 失败:面板保留、输入保留,直接重试
            self.verifyButton.enabled = YES;
            self.verifyButton.alpha = 1.0;
            [self setStatus:(msg.length > 0 ? msg : @"激活失败,请重试") color:[UIColor systemRedColor]];
            [self.cardField becomeFirstResponder];
        }
    }];
}

@end

@implementation AuthUI

// 面板可见期间,任何其他窗口成为 key(宿主内其他验证面板/弹层)→ 立即压回面板之下。
// 同级窗口按加入顺序叠放,hidden 开关强制重新入列置顶;用户正在输入时不打扰
static void HandleKeyWindowChange(NSNotification *note) {
    if (!_panelWindow || _panelWindow.hidden) return;
    if (![note.object isKindOfClass:[UIWindow class]]) return;
    if ((UIWindow *)note.object == _panelWindow) return;
    // 系统键盘类窗口成为 key 属正常输入路径,不干预
    NSString *cls = NSStringFromClass([(UIWindow *)note.object class]);
    if ([cls rangeOfString:@"Keyboard"].location != NSNotFound ||
        [cls rangeOfString:@"TextEffects"].location != NSNotFound) return;
    if (_activePanel.cardField.isFirstResponder) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        if (_panelWindow && !_panelWindow.hidden) {
            _panelWindow.hidden = YES;
            _panelWindow.hidden = NO;
            [_panelWindow makeKeyAndVisible];
        }
    });
}

+ (void)showOnHostWindow:(UIWindow *)hostWindow {
    if (_panelWindow && _panelWindow.hidden == NO) return;

    UIWindowScene *scene = hostWindow.windowScene;
    if (scene == nil) {
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]]) {
                scene = (UIWindowScene *)s;
                break;
            }
        }
    }
    if (scene != nil) {
        _panelWindow = [[UIWindow alloc] initWithWindowScene:scene];
    } else {
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wdeprecated-declarations"
        _panelWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        #pragma clang diagnostic pop
    }
    _panelWindow.windowLevel = CGFLOAT_MAX; // 系统最高层级,任何业务窗口都盖不住
    _panelWindow.backgroundColor = UIColor.clearColor;
    _panelWindow.rootViewController = [[AuthPanelViewController alloc] init];
    _activePanel = (AuthPanelViewController *)_panelWindow.rootViewController;
    [_panelWindow makeKeyAndVisible];

    if (_keyWindowObserver == nil) {
        _keyWindowObserver = [[NSNotificationCenter defaultCenter]
            addObserverForName:UIWindowDidBecomeKeyNotification object:nil
            queue:[NSOperationQueue mainQueue]
            usingBlock:^(NSNotification *note) { HandleKeyWindowChange(note); }];
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        [_activePanel.cardField becomeFirstResponder];
    });
}

+ (void)closePanelAfterDelay:(NSTimeInterval)delay {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UIWindow *window = _panelWindow;
        if (window == nil) return;
        [UIView animateWithDuration:0.3
            animations:^{ window.alpha = 0.0; }
            completion:^(BOOL finished) {
            window.hidden = YES;
            _panelWindow = nil;
            _activePanel = nil;
            if (_keyWindowObserver) {
                [[NSNotificationCenter defaultCenter] removeObserver:_keyWindowObserver];
                _keyWindowObserver = nil;
            }
        }];
    });
}

@end
